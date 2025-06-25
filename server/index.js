const express = require('express');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5001;

// Middleware
app.use(cors());
app.use(express.json());

// In-memory data storage
const users = [
  { id: 1, firebase_uid: 'admin-1', email: 'admin@evcon.com', name: 'Admin User', role: 'admin' },
  { id: 2, firebase_uid: 'control-1', email: 'control@evcon.com', name: 'Control User', role: 'user' },
  { id: 3, firebase_uid: 'obstacle-1', email: 'obstacle@evcon.com', name: 'Obstacle User', role: 'user' },
  { id: 4, firebase_uid: 'control-2', email: 'lisa@evcon.com', name: 'Lisa Control', role: 'user' },
  { id: 5, firebase_uid: 'obstacle-2', email: 'david@evcon.com', name: 'David Obstacle', role: 'user' }
];

const events = [
  { id: 1, name: 'Summer Festival 2024', description: 'Annual summer celebration', start_date: '2024-07-15', end_date: '2024-07-17', location: 'Central Park', status: 'active', created_by: 1 },
  { id: 2, name: 'Tech Conference', description: 'Technology innovation summit', start_date: '2024-08-20', end_date: '2024-08-22', location: 'Convention Center', status: 'active', created_by: 1 },
  { id: 3, name: 'Music Concert', description: 'Live music performance', start_date: '2024-09-10', end_date: '2024-09-10', location: 'Arena', status: 'active', created_by: 2 },
  { id: 4, name: 'Sports Tournament', description: 'Annual sports competition', start_date: '2024-10-05', end_date: '2024-10-07', location: 'Sports Complex', status: 'active', created_by: 3 }
];

const eventAssignments = [
  { id: 1, event_id: 1, user_id: 1, role: 'organizer' },
  { id: 2, event_id: 1, user_id: 2, role: 'control' },
  { id: 3, event_id: 1, user_id: 3, role: 'obstacle' },
  { id: 4, event_id: 2, user_id: 1, role: 'organizer' },
  { id: 5, event_id: 2, user_id: 4, role: 'control' },
  { id: 6, event_id: 3, user_id: 2, role: 'organizer' },
  { id: 7, event_id: 3, user_id: 5, role: 'obstacle' },
  { id: 8, event_id: 4, user_id: 3, role: 'organizer' }
];

const eventLogs = [
  { 
    id: 1, 
    event_id: 1, 
    parent_id: null, 
    version_id: 'log_1_v1', 
    log_type: 'First Aid', 
    reported_by: 'John Doe', 
    detail: 'Equipment malfunction during setup', 
    custom_fields: {
      patient_name: 'Sarah Johnson',
      patient_age: '25',
      injury_type: 'Minor',
      location: 'Main Stage Area',
      action_taken: 'Applied first aid kit, cleaned wound',
      medical_contact: true,
      ambulance_called: false
    },
    resolved: false, 
    created_by: 2, 
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  },
  { 
    id: 2, 
    event_id: 1, 
    parent_id: 1, 
    version_id: 'log_1_v1_response_1', 
    log_type: 'response', 
    reported_by: 'Tech Team', 
    detail: 'Equipment replaced and tested', 
    custom_fields: {},
    resolved: true, 
    created_by: 1, 
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  },
  { 
    id: 3, 
    event_id: 2, 
    parent_id: null, 
    version_id: 'log_2_v1', 
    log_type: 'Lost Child', 
    reported_by: 'Security Team', 
    detail: 'Crowd control measures implemented', 
    custom_fields: {
      child_name: 'Emma Wilson',
      child_age: '8',
      last_seen_location: 'Food Court Area',
      last_seen_time: '14:30',
      child_description: 'Blonde hair, blue dress, carrying pink backpack',
      parent_contact: '555-0123',
      police_notified: true
    },
    resolved: false, 
    created_by: 4, 
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  }
];

const activityLogs = [
  { id: 1, user_id: 1, user_email: 'admin@evcon.com', user_name: 'Admin User', action: 'login', resource_type: 'user', resource_id: 1, resource_name: 'admin@evcon.com', details: '{"ip": "127.0.0.1"}', ip_address: '127.0.0.1', user_agent: 'Mozilla/5.0', created_at: new Date().toISOString() },
  { id: 2, user_id: 2, user_email: 'control@evcon.com', user_name: 'Control User', action: 'view_events', resource_type: 'events', resource_id: null, resource_name: null, details: '{"count": 4}', ip_address: '127.0.0.1', user_agent: 'Mozilla/5.0', created_at: new Date().toISOString() },
  { id: 3, user_id: 1, user_email: 'admin@evcon.com', user_name: 'Admin User', action: 'create_event', resource_type: 'event', resource_id: 4, resource_name: 'Sports Tournament', details: '{"description": "Annual sports competition"}', ip_address: '127.0.0.1', user_agent: 'Mozilla/5.0', created_at: new Date().toISOString() }
];

// Event preferences/templates storage
let eventPreferences = {
  templates: {
    'First Aid': {
      enabled: true,
      fields: [
        { name: 'patient_name', label: 'Patient Name', type: 'text', required: true },
        { name: 'patient_age', label: 'Patient Age', type: 'number', required: true },
        { name: 'injury_type', label: 'Type of Injury', type: 'select', options: ['Minor', 'Major', 'Medical Emergency'], required: true },
        { name: 'location', label: 'Location of Incident', type: 'text', required: true },
        { name: 'action_taken', label: 'Action Taken', type: 'textarea', required: true },
        { name: 'medical_contact', label: 'Medical Contact Called', type: 'checkbox', required: false },
        { name: 'ambulance_called', label: 'Ambulance Called', type: 'checkbox', required: false }
      ]
    },
    'Lost Child': {
      enabled: true,
      fields: [
        { name: 'child_name', label: 'Child Name', type: 'text', required: true },
        { name: 'child_age', label: 'Child Age', type: 'number', required: true },
        { name: 'last_seen_location', label: 'Last Seen Location', type: 'text', required: true },
        { name: 'last_seen_time', label: 'Last Seen Time', type: 'time', required: true },
        { name: 'child_description', label: 'Child Description', type: 'textarea', required: true },
        { name: 'parent_contact', label: 'Parent/Guardian Contact', type: 'text', required: true },
        { name: 'police_notified', label: 'Police Notified', type: 'checkbox', required: false }
      ]
    },
    'Found Child': {
      enabled: true,
      fields: [
        { name: 'child_name', label: 'Child Name', type: 'text', required: false },
        { name: 'child_age', label: 'Child Age', type: 'number', required: false },
        { name: 'found_location', label: 'Found Location', type: 'text', required: true },
        { name: 'found_time', label: 'Found Time', type: 'time', required: true },
        { name: 'child_description', label: 'Child Description', type: 'textarea', required: true },
        { name: 'parent_contact', label: 'Parent/Guardian Contact', type: 'text', required: false },
        { name: 'reunited', label: 'Reunited with Parent/Guardian', type: 'checkbox', required: false }
      ]
    },
    'General': {
      enabled: true,
      fields: [
        { name: 'incident_type', label: 'Incident Type', type: 'text', required: true },
        { name: 'location', label: 'Location', type: 'text', required: true },
        { name: 'description', label: 'Description', type: 'textarea', required: true },
        { name: 'severity', label: 'Severity', type: 'select', options: ['Low', 'Medium', 'High', 'Critical'], required: true },
        { name: 'action_required', label: 'Action Required', type: 'textarea', required: false }
      ]
    }
  }
};

// Helper function to log activity
const logActivity = (req, user, action, resourceType = null, resourceId = null, resourceName = null, details = {}) => {
  const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
  const userAgent = req.headers['user-agent'];
  
  const newLog = {
    id: activityLogs.length + 1,
    user_id: user ? user.id : null,
    user_email: user ? user.email : null,
    user_name: user ? user.name : null,
    action,
    resource_type: resourceType,
    resource_id: resourceId,
    resource_name: resourceName,
    details: JSON.stringify(details),
    ip_address: ipAddress,
    user_agent: userAgent,
    created_at: new Date().toISOString()
  };
  
  activityLogs.push(newLog);
  console.log(`Activity logged: ${action} by ${user ? user.email : 'unknown'}`);
};

// Middleware to verify mock token
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    // Decode mock token (base64 encoded JSON)
    try {
      const decoded = JSON.parse(Buffer.from(token, 'base64').toString());
      if (decoded.uid && decoded.email) {
        // Find user in our in-memory storage
        const user = users.find(u => u.firebase_uid === decoded.uid);
        if (user) {
          req.user = user;
          next();
          return;
        }
      }
    } catch (e) {
      console.error('Token decode error:', e);
    }

    res.status(403).json({ error: 'Invalid token' });
  } catch (error) {
    console.error('Token verification failed:', error);
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes

// Get all events (with user permissions)
app.get('/api/events', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    let filteredEvents = events.filter(e => e.status === 'active');
    
    // If not admin, only show events user is assigned to
    if (user.role !== 'admin') {
      const userAssignments = eventAssignments.filter(ea => ea.user_id === user.id);
      const assignedEventIds = userAssignments.map(ea => ea.event_id);
      filteredEvents = filteredEvents.filter(e => 
        e.created_by === user.id || assignedEventIds.includes(e.id)
      );
    }
    
    // Add created_by_name to events
    const eventsWithNames = filteredEvents.map(event => ({
      ...event,
      created_by_name: users.find(u => u.id === event.created_by)?.name || 'Unknown'
    }));
    
    // Log the activity
    logActivity(req, user, 'view_events', 'events', null, null, { count: eventsWithNames.length });
    
    res.json(eventsWithNames);
  } catch (error) {
    console.error('Error fetching events:', error);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// Create new event
app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const { name, description, start_date, end_date, location } = req.body;

    const newEvent = {
      id: events.length + 1,
      name,
      description,
      start_date,
      end_date,
      location,
      status: 'active',
      created_by: user.id
    };

    events.push(newEvent);

    // Auto-assign creator as organizer
    const newAssignment = {
      id: eventAssignments.length + 1,
      event_id: newEvent.id,
      user_id: user.id,
      role: 'organizer'
    };
    eventAssignments.push(newAssignment);

    // Log the activity
    logActivity(req, user, 'create_event', 'event', newEvent.id, name, {
      description,
      start_date,
      end_date,
      location
    });

    res.json(newEvent);
  } catch (error) {
    console.error('Error creating event:', error);
    res.status(500).json({ error: 'Failed to create event' });
  }
});

// Get event logs
app.get('/api/events/:eventId/logs', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const eventId = parseInt(req.params.eventId);

    // Admins can always access
    if (user.role === 'admin') {
      const logs = eventLogs
        .filter(log => log.event_id === eventId)
        .map(log => ({
          ...log,
          created_by_name: users.find(u => u.id === log.created_by)?.name || 'Unknown'
        }));
      
      // Log the activity
      logActivity(req, user, 'view_event_logs', 'event', eventId, null, { log_count: logs.length });
      
      return res.json(logs);
    }

    // Check if user has access to this event
    const event = events.find(e => e.id === eventId);
    const assignment = eventAssignments.find(ea => ea.event_id === eventId && ea.user_id === user.id);
    
    if (!event || (event.created_by !== user.id && !assignment)) {
      return res.status(403).json({ error: 'Access denied to this event' });
    }

    const logs = eventLogs
      .filter(log => log.event_id === eventId)
      .map(log => ({
        ...log,
        created_by_name: users.find(u => u.id === log.created_by)?.name || 'Unknown'
      }));

    // Log the activity
    logActivity(req, user, 'view_event_logs', 'event', eventId, null, { log_count: logs.length });

    res.json(logs);
  } catch (error) {
    console.error('Error fetching event logs:', error);
    res.status(500).json({ error: 'Failed to fetch event logs' });
  }
});

// Create new log entry
app.post('/api/events/:eventId/logs', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const eventId = parseInt(req.params.eventId);
    const { log_type, reported_by, detail, parent_id, custom_fields } = req.body;

    // Admins can always access
    if (user.role !== 'admin') {
      // Check if user has access to this event
      const event = events.find(e => e.id === eventId);
      const assignment = eventAssignments.find(ea => ea.event_id === eventId && ea.user_id === user.id);
      
      if (!event || (event.created_by !== user.id && !assignment)) {
        return res.status(403).json({ error: 'Access denied to this event' });
      }
    }

    // Generate version ID
    let versionId = `log_${Date.now()}_v1`;
    if (parent_id) {
      // For threaded responses, use parent's version ID with suffix
      const parentLog = eventLogs.find(log => log.id === parent_id);
      if (parentLog) {
        versionId = `${parentLog.version_id}_response_${Date.now()}`;
      }
    }

    const newLog = {
      id: eventLogs.length + 1,
      event_id: eventId,
      parent_id: parent_id || null,
      version_id: versionId,
      log_type,
      reported_by,
      detail,
      custom_fields: custom_fields || {},
      resolved: false,
      created_by: user.id,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };

    eventLogs.push(newLog);

    // Get the created log with user info
    const logWithUser = {
      ...newLog,
      created_by_name: users.find(u => u.id === newLog.created_by)?.name || 'Unknown'
    };

    // Log the activity
    logActivity(req, user, 'add_log_entry', 'log', newLog.id, log_type, {
      event_id: eventId,
      reported_by,
      detail,
      parent_id,
      custom_fields_count: Object.keys(custom_fields || {}).length
    });

    res.json(logWithUser);
  } catch (error) {
    console.error('Error creating log entry:', error);
    res.status(500).json({ error: 'Failed to create log entry', details: error.message });
  }
});

// Update log entry (creates new version)
app.put('/api/logs/:logId', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    const logId = parseInt(req.params.logId);
    const { log_type, reported_by, detail, resolved, custom_fields } = req.body;

    // Get original log
    const originalLog = eventLogs.find(log => log.id === logId);

    if (!originalLog) {
      return res.status(404).json({ error: 'Log entry not found' });
    }

    // Admins can always access
    if (user.role !== 'admin') {
      // Check if user has access to this event
      const event = events.find(e => e.id === originalLog.event_id);
      const assignment = eventAssignments.find(ea => ea.event_id === originalLog.event_id && ea.user_id === user.id);
      
      if (!event || (event.created_by !== user.id && !assignment)) {
        return res.status(403).json({ error: 'Access denied to this event' });
      }
    }

    // Generate new version ID
    const baseVersionId = originalLog.version_id.split('_v')[0];
    const versionNumber = parseInt(originalLog.version_id.split('_v')[1] || '1') + 1;
    const newVersionId = `${baseVersionId}_v${versionNumber}`;

    // Create new version
    const newLog = {
      id: eventLogs.length + 1,
      event_id: originalLog.event_id,
      parent_id: originalLog.parent_id,
      version_id: newVersionId,
      log_type,
      reported_by,
      detail,
      custom_fields: custom_fields || {},
      resolved,
      created_by: user.id,
      created_at: originalLog.created_at,
      updated_at: new Date().toISOString()
    };

    eventLogs.push(newLog);

    // Get the updated log with user info
    const logWithUser = {
      ...newLog,
      created_by_name: users.find(u => u.id === newLog.created_by)?.name || 'Unknown'
    };

    // Log the activity
    logActivity(req, user, 'edit_log_entry', 'log', newLog.id, log_type, {
      original_log_id: logId,
      event_id: originalLog.event_id,
      reported_by,
      detail,
      resolved,
      custom_fields_count: Object.keys(custom_fields || {}).length
    });

    res.json(logWithUser);
  } catch (error) {
    console.error('Error updating log entry:', error);
    res.status(500).json({ error: 'Failed to update log entry', details: error.message });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Log the activity
    logActivity(req, user, 'view_profile', 'user', user.id, user.email);
    
    res.json(user);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// Admin: Get activity logs
app.get('/api/admin/activity-logs', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Only admins can access activity logs
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { 
      page = 1, 
      limit = 50, 
      action = null, 
      user_id = null, 
      resource_type = null,
      start_date = null,
      end_date = null 
    } = req.query;

    let filteredLogs = [...activityLogs];

    // Apply filters
    if (action) {
      filteredLogs = filteredLogs.filter(log => log.action === action);
    }
    if (user_id) {
      filteredLogs = filteredLogs.filter(log => log.user_id === parseInt(user_id));
    }
    if (resource_type) {
      filteredLogs = filteredLogs.filter(log => log.resource_type === resource_type);
    }
    if (start_date) {
      filteredLogs = filteredLogs.filter(log => new Date(log.created_at) >= new Date(start_date));
    }
    if (end_date) {
      filteredLogs = filteredLogs.filter(log => new Date(log.created_at) <= new Date(end_date));
    }

    // Sort by created_at DESC
    filteredLogs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    // Pagination
    const offset = (page - 1) * limit;
    const paginatedLogs = filteredLogs.slice(offset, offset + parseInt(limit));

    // Log the activity
    logActivity(req, user, 'view_activity_logs', 'system', null, null, {
      page,
      limit,
      total: filteredLogs.length,
      filters: { action, user_id, resource_type, start_date, end_date }
    });

    res.json({
      logs: paginatedLogs,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredLogs.length,
        pages: Math.ceil(filteredLogs.length / limit)
      }
    });
  } catch (error) {
    console.error('Error fetching activity logs:', error);
    res.status(500).json({ error: 'Failed to fetch activity logs' });
  }
});

// Admin: Get activity log statistics
app.get('/api/admin/activity-stats', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Only admins can access activity stats
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Get logs from last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    
    const recentLogs = activityLogs.filter(log => new Date(log.created_at) >= sevenDaysAgo);

    // Get action counts
    const actionStats = {};
    recentLogs.forEach(log => {
      actionStats[log.action] = (actionStats[log.action] || 0) + 1;
    });

    // Get user activity counts
    const userStats = {};
    recentLogs.forEach(log => {
      if (log.user_id) {
        const key = `${log.user_name} (${log.user_email})`;
        userStats[key] = (userStats[key] || 0) + 1;
      }
    });

    // Get recent activity (last 20)
    const recentActivity = activityLogs
      .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
      .slice(0, 20);

    res.json({
      actionStats: Object.entries(actionStats).map(([action, count]) => ({ action, count })),
      userStats: Object.entries(userStats).map(([user, count]) => ({ user_name: user.split(' (')[0], user_email: user.match(/\((.*?)\)/)?.[1] || '', count })),
      recentActivity
    });
  } catch (error) {
    console.error('Error fetching activity stats:', error);
    res.status(500).json({ error: 'Failed to fetch activity stats' });
  }
});

// Admin: Log authentication event (called from frontend)
app.post('/api/log-auth-event', async (req, res) => {
  try {
    const { action, user_id, user_email, user_name, details } = req.body;
    
    // Get IP address and user agent
    const ipAddress = req.ip || req.connection.remoteAddress || req.headers['x-forwarded-for'];
    const userAgent = req.headers['user-agent'];
    
    const newLog = {
      id: activityLogs.length + 1,
      user_id: user_id ? parseInt(user_id) : null,
      user_email,
      user_name,
      action,
      resource_type: 'user',
      resource_id: null,
      resource_name: user_email,
      details: JSON.stringify(details),
      ip_address: ipAddress,
      user_agent: userAgent,
      created_at: new Date().toISOString()
    };

    activityLogs.push(newLog);

    res.json({ success: true });
  } catch (error) {
    console.error('Error logging auth event:', error);
    res.status(500).json({ error: 'Failed to log auth event' });
  }
});

// Admin: Get event preferences/templates
app.get('/api/admin/event-preferences', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Only admins can access event preferences
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    // Log the activity
    logActivity(req, user, 'view_event_preferences', 'system', null, null, {});

    res.json(eventPreferences);
  } catch (error) {
    console.error('Error fetching event preferences:', error);
    res.status(500).json({ error: 'Failed to fetch event preferences' });
  }
});

// Admin: Save event preferences/templates
app.post('/api/admin/event-preferences', authenticateToken, async (req, res) => {
  try {
    const user = req.user;
    
    // Only admins can save event preferences
    if (user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    const { templates } = req.body;
    
    // Update the event preferences
    eventPreferences = { templates };

    // Log the activity
    logActivity(req, user, 'save_event_preferences', 'system', null, null, {
      template_count: Object.keys(templates).length,
      enabled_templates: Object.keys(templates).filter(key => templates[key].enabled)
    });

    res.json({ success: true, message: 'Event preferences saved successfully' });
  } catch (error) {
    console.error('Error saving event preferences:', error);
    res.status(500).json({ error: 'Failed to save event preferences' });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  console.log('Using in-memory storage (no database required)');
}); 