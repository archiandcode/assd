CREATE TABLE IF NOT EXISTS pdf_files (
	id TEXT PRIMARY KEY,
	file_path TEXT NOT NULL,
	original_name TEXT NOT NULL,
	link_path TEXT NOT NULL,
	size BIGINT NOT NULL,
	created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS pdf_files_original_name_idx ON pdf_files (LOWER(original_name));
CREATE INDEX IF NOT EXISTS pdf_files_link_path_idx ON pdf_files (LOWER(link_path));
