SELECT id, username, role, department FROM users;


SELECT file_id, original_filename, sender_id, receiver_id, created_at FROM file_metadata;

SELECT id, sender_id, receiver_id, is_deleted, created_at FROM messages;

SELECT * FROM file_access_log 
WHERE file_id = 1; -- Replace 1 with your desired file_id;


SELECT f.original_filename, s.username AS sender, r.username AS receiver 
FROM file_metadata f
JOIN users s ON f.sender_id = s.id
JOIN users r ON f.receiver_id = r.id;