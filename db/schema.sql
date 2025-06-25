-- Database schema for Evcon Event Control System

-- Users table (extends Firebase auth)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    firebase_uid VARCHAR(255) UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user', -- 'admin', 'staff', 'user'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Events table
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    start_date TIMESTAMP NOT NULL,
    end_date TIMESTAMP NOT NULL,
    location TEXT,
    status VARCHAR(50) DEFAULT 'active', -- 'active', 'completed', 'cancelled'
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Event assignments (who is assigned to which events)
CREATE TABLE IF NOT EXISTS event_assignments (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL, -- 'organizer', 'staff', 'volunteer'
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(event_id, user_id)
);

-- Event control log entries
CREATE TABLE IF NOT EXISTS event_logs (
    id SERIAL PRIMARY KEY,
    event_id INTEGER REFERENCES events(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES event_logs(id) ON DELETE CASCADE, -- For threaded responses
    version_id VARCHAR(50) NOT NULL, -- Format: original_id_v2, original_id_v3, etc.
    log_type VARCHAR(50) NOT NULL, -- 'General', 'First Aid', 'Lost Child', 'Found Child'
    reported_by TEXT NOT NULL, -- Who reported the incident
    detail TEXT NOT NULL,
    resolved BOOLEAN DEFAULT FALSE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Activity logs table (for comprehensive system logging)
CREATE TABLE IF NOT EXISTS activity_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    user_email TEXT,
    user_name TEXT,
    action VARCHAR(100) NOT NULL, -- 'login', 'logout', 'create_event', 'add_log', 'edit_log', etc.
    resource_type VARCHAR(50), -- 'event', 'log', 'user', 'system'
    resource_id INTEGER, -- ID of the affected resource
    resource_name TEXT, -- Name/description of the affected resource
    details JSONB, -- Additional details about the action
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for better performance
CREATE INDEX IF NOT EXISTS idx_event_logs_event_id ON event_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_event_logs_parent_id ON event_logs(parent_id);
CREATE INDEX IF NOT EXISTS idx_event_logs_version_id ON event_logs(version_id);
CREATE INDEX IF NOT EXISTS idx_event_assignments_event_id ON event_assignments(event_id);
CREATE INDEX IF NOT EXISTS idx_event_assignments_user_id ON event_assignments(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_user_id ON activity_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_action ON activity_logs(action);
CREATE INDEX IF NOT EXISTS idx_activity_logs_created_at ON activity_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_activity_logs_resource_type ON activity_logs(resource_type);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers to automatically update updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_events_updated_at BEFORE UPDATE ON events
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_event_logs_updated_at BEFORE UPDATE ON event_logs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column(); 