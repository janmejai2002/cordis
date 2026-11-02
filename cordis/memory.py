"""Episodic Memory Ledger: SQLite FTS5 BM25 + Word-Stem + Tag Reciprocal Rank Fusion (RRF).
Includes explicit `status='superseded'` invalidation and `flake_retry_count` tracking.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class MemoryRecord:
    record_id: int
    ast_anchor: str
    function_name: str
    failure_mode: str
    summary: str
    tags: str
    flake_retry_count: int
    status: str
    rrf_score: float = 0.0


class EpisodicMemoryLedger:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS memory_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ast_anchor TEXT NOT NULL,
                function_name TEXT NOT NULL,
                failure_mode TEXT NOT NULL,
                summary TEXT NOT NULL,
                tags TEXT NOT NULL,
                flake_retry_count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                superseded_by INTEGER DEFAULT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts USING fts5(
                function_name,
                failure_mode,
                summary,
                tags,
                content='memory_entries',
                content_rowid='id',
                tokenize='porter unicode61'
            )
            """
        )
        self.conn.commit()

    def record_outcome(
        self,
        ast_anchor: str,
        function_name: str,
        failure_mode: str,
        summary: str,
        tags: str,
        supersede_previous_for_anchor: bool = False,
    ) -> int:
        cur = self.conn.cursor()
        if supersede_previous_for_anchor:
            cur.execute(
                "UPDATE memory_entries SET status = 'superseded' WHERE ast_anchor = ? AND status = 'active'",
                (ast_anchor,),
            )

        # Check if identical failure_mode exists for this anchor (increment flake_retry_count instead of permanent blind prune)
        cur.execute(
            """
            SELECT id, flake_retry_count FROM memory_entries
            WHERE ast_anchor = ? AND failure_mode = ? AND status = 'active'
            """,
            (ast_anchor, failure_mode),
        )
        existing = cur.fetchone()
        if existing and not supersede_previous_for_anchor:
            rec_id, retries = existing
            cur.execute(
                "UPDATE memory_entries SET flake_retry_count = ?, summary = ? WHERE id = ?",
                (retries + 1, summary, rec_id),
            )
            self.conn.commit()
            return int(rec_id)

        cur.execute(
            """
            INSERT INTO memory_entries (ast_anchor, function_name, failure_mode, summary, tags, flake_retry_count, status)
            VALUES (?, ?, ?, ?, ?, 1, 'active')
            """,
            (ast_anchor, function_name, failure_mode, summary, tags),
        )
        new_id = int(cur.lastrowid)
        cur.execute(
            """
            INSERT INTO memory_fts(rowid, function_name, failure_mode, summary, tags)
            VALUES (?, ?, ?, ?, ?)
            """,
            (new_id, function_name, failure_mode, summary, tags),
        )
        self.conn.commit()
        return new_id

    def recall_rrf(self, query_text: str, tag_filter: Optional[str] = None, top_k: int = 5) -> List[MemoryRecord]:
        """Recalls active (non-superseded) memories using 3-channel Reciprocal Rank Fusion (RRF):
        Channel 1: SQLite FTS5 BM25 ranking (with Porter word-stemming)
        Channel 2: Exact function/identifier token match
        Channel 3: Tag overlap
        """
        cur = self.conn.cursor()
        tokens = [t.strip() for t in query_text.replace(":", " ").replace("_", " ").split() if t.strip()]
        fts_query = " OR ".join(f'"{t}"' for t in tokens) if tokens else '""'

        bm25_ranks: dict[int, int] = {}
        try:
            cur.execute(
                """
                SELECT rowid, bm25(memory_fts) as score
                FROM memory_fts
                WHERE memory_fts MATCH ?
                ORDER BY score ASC
                LIMIT 25
                """,
                (fts_query,),
            )
            for rank_idx, (rowid, _) in enumerate(cur.fetchall(), start=1):
                bm25_ranks[int(rowid)] = rank_idx
        except sqlite3.OperationalError:
            pass

        cur.execute(
            """
            SELECT id, ast_anchor, function_name, failure_mode, summary, tags, flake_retry_count, status
            FROM memory_entries
            WHERE status = 'active'
            """
        )
        rows = cur.fetchall()

        scored_records: List[MemoryRecord] = []
        k_rrf = 60.0
        q_lower = query_text.lower()

        for row in rows:
            rec_id, anchor, fn_name, f_mode, summary, tags, retries, status = row
            rrf = 0.0
            # Channel 1: FTS5 BM25
            if rec_id in bm25_ranks:
                rrf += 1.0 / (k_rrf + bm25_ranks[rec_id])
            # Channel 2: Function / Anchor match
            if fn_name.lower() in q_lower or anchor.lower() in q_lower:
                rrf += 1.0 / (k_rrf + 1.0)
            # Channel 3: Tag match
            if tag_filter and tag_filter.lower() in tags.lower():
                rrf += 1.0 / (k_rrf + 1.0)
            elif any(tok.lower() in tags.lower() for tok in tokens):
                rrf += 1.0 / (k_rrf + 3.0)

            if rrf > 0:
                scored_records.append(
                    MemoryRecord(
                        record_id=rec_id,
                        ast_anchor=anchor,
                        function_name=fn_name,
                        failure_mode=f_mode,
                        summary=summary,
                        tags=tags,
                        flake_retry_count=retries,
                        status=status,
                        rrf_score=round(rrf, 6),
                    )
                )

        scored_records.sort(key=lambda r: r.rrf_score, reverse=True)
        return scored_records[:top_k]

    def close(self) -> None:
        self.conn.close()