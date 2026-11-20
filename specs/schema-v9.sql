ALTER TABLE resources
ADD COLUMN source_agent_id TEXT REFERENCES agents(agent_id);

CREATE INDEX resources_source_agent
ON resources(source_agent_id, content_id)
WHERE source_agent_id IS NOT NULL;
