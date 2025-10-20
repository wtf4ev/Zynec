package com.mycompany.zynecprj;

import static spark.Spark.*;
import java.sql.*;
import java.nio.file.*;
import org.mindrot.jbcrypt.BCrypt;
import spark.Session;
import java.util.*;
import com.google.gson.Gson;
import java.util.Base64;
import java.io.InputStream;
import javax.servlet.MultipartConfigElement;
import javax.servlet.http.Part;

public class LoginHandler {

    private static Connection connect() throws SQLException {
        try {
            Path dataDir = Paths.get("data");
            if (!Files.exists(dataDir)) Files.createDirectories(dataDir);
            String dbPath = dataDir.resolve("zynec.db").toAbsolutePath().toString();
            return DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        } catch (Exception e) { throw new SQLException("DB connect failed", e); }
    }

    private static void initializeDatabase() {
        try (Connection conn = connect(); Statement stmt = conn.createStatement()) {

            // USERS
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS users (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT UNIQUE," +
                    "password_hash TEXT," +
                    "profile_pic TEXT," +
                    "bio TEXT," +
                    "branch TEXT," +
                    "semester INTEGER," +
                    "flairs TEXT)");

            // COMMUNITIES
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS communities (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "name TEXT UNIQUE," +
                    "icon TEXT," +
                    "owner TEXT)");

            // MEMBERS
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS members (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "username TEXT," +
                    "community_id INTEGER," +
                    "role TEXT)");

            // POSTS
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS posts (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "community_id INTEGER," +
                    "author TEXT," +
                    "content TEXT," +
                    "media TEXT," +
                    "likes TEXT," +
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");

            // COMMENTS
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS comments (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "post_id INTEGER," +
                    "author TEXT," +
                    "comment TEXT," +
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");

            // POLLS
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS polls (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                    "community_id INTEGER," +
                    "question TEXT," +
                    "options TEXT," +
                    "votes TEXT," +
                    "author TEXT)");

            // Insert communities
            stmt.executeUpdate("INSERT OR IGNORE INTO communities (name, icon, owner) VALUES " +
                    "('Root','root_icon.png','chaaru')," +
                    "('Foss Riet','foss_icon.png','chaaru')," +
                    "('Raise','raise_icon.png','chaaru')");

            // Insert chaaru as admin/owner
            stmt.executeUpdate("INSERT OR IGNORE INTO users (username,password_hash) VALUES ('chaaru','" +
                    BCrypt.hashpw("chaaru@06", BCrypt.gensalt()) + "')");

            // Insert dummy users
            for(int i=1;i<=7;i++){
                stmt.executeUpdate("INSERT OR IGNORE INTO users (username, password_hash) VALUES ('user"+i+"','"+
                        BCrypt.hashpw("password",BCrypt.gensalt())+"')");
            }

            // Assign chaaru as owner in all communities
            ResultSet rs = stmt.executeQuery("SELECT id FROM communities");
            while(rs.next()){
                int cid = rs.getInt("id");
                stmt.executeUpdate("INSERT OR IGNORE INTO members (username,community_id,role) VALUES ('chaaru',"+cid+",'owner')");
            }

            // Dummy members for Foss Riet (community_id=2)
            int fossRietId = 2;
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user1', " + fossRietId + ", 'member')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user2', " + fossRietId + ", 'member')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user3', " + fossRietId + ", 'admin')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user4', " + fossRietId + ", 'member')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user5', " + fossRietId + ", 'member')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user6', " + fossRietId + ", 'member')");
            stmt.executeUpdate("INSERT OR IGNORE INTO members (username, community_id, role) VALUES ('user7', " + fossRietId + ", 'member')");

        } catch (SQLException e) { System.err.println(e.getMessage()); }
    }

    private static boolean validateLogin(String username, String password) {
        String sql = "SELECT password_hash FROM users WHERE username = ?";
        try (Connection conn = connect(); PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) return BCrypt.checkpw(password, rs.getString("password_hash"));
        } catch (SQLException e) { System.err.println(e.getMessage()); }
        return false;
    }

    public static void main(String[] args) {
        port(4567);
        staticFiles.externalLocation("web");
        Gson gson = new Gson();

        initializeDatabase();

        // REGISTER
        post("/register",(req,res)->{
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            if(username==null||password==null) {
                res.status(400); return "Missing fields";
            }
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement("INSERT INTO users(username,password_hash) VALUES(?,?)")){
                ps.setString(1, username);
                ps.setString(2, BCrypt.hashpw(password,BCrypt.gensalt()));
                ps.executeUpdate();
                res.status(200);
                return "Registration successful!";
            }catch(SQLException e){
                res.status(500);
                if(e.getMessage().contains("UNIQUE")) return "Username exists!";
                return "Registration failed";
            }
        });

        // LOGIN
        post("/login",(req,res)->{
            String username = req.queryParams("username");
            String password = req.queryParams("password");
            if(validateLogin(username,password)){
                Session session = req.session(true);
                session.attribute("username",username);
                return "Login successful!";
            }else return "Invalid credentials";
        });

        // GET USER ROLE IN COMMUNITY
        get("/api/community/:name/role",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("role", "guest"));
            }
            String username = session.attribute("username");
            String communityName = req.params(":name");
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?")){
                ps.setString(1, communityName);
                ps.setString(2, username);
                ResultSet rs = ps.executeQuery();
                if(rs.next()){
                    return gson.toJson(Map.of("role", rs.getString("role")));
                }else{
                    return gson.toJson(Map.of("role", "guest"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("role", "guest", "error", e.getMessage()));
            }
        });

        // GET COMMUNITY MEMBERS
        get("/api/community/:name/members",(req,res)->{
            res.type("application/json");
            String communityName = req.params(":name");
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT m.username, m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ?")){
                ps.setString(1, communityName);
                ResultSet rs = ps.executeQuery();
                List<Map<String,String>> members = new ArrayList<>();
                while(rs.next()){
                    Map<String,String> member = new HashMap<>();
                    member.put("username", rs.getString("username"));
                    member.put("role", rs.getString("role"));
                    members.add(member);
                }
                return gson.toJson(members);
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // GET COMMUNITY POSTS
        get("/api/community/:name/posts",(req,res)->{
            res.type("application/json");
            String communityName = req.params(":name");
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT p.id, p.username, p.content, p.media, p.likes, p.timestamp " +
                    "FROM posts p JOIN communities c ON p.community_id = c.id " +
                    "WHERE c.name = ? ORDER BY p.timestamp DESC")){
                ps.setString(1, communityName);
                ResultSet rs = ps.executeQuery();
                List<Map<String,Object>> posts = new ArrayList<>();
                while(rs.next()){
                    Map<String,Object> post = new HashMap<>();
                    post.put("id", rs.getInt("id"));
                    post.put("author", rs.getString("username"));
                    post.put("content", rs.getString("content"));
                    post.put("media", rs.getString("media"));
                    post.put("likes", rs.getString("likes"));
                    post.put("timestamp", rs.getString("timestamp"));
                    posts.add(post);
                }
                return gson.toJson(posts);
            }catch(SQLException e){
                System.err.println("Error fetching posts: " + e.getMessage());
                return gson.toJson(new ArrayList<>());
            }
        });

        // GET COMMUNITY POLLS
        get("/api/community/:name/polls",(req,res)->{
            res.type("application/json");
            String communityName = req.params(":name");
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT p.id, p.question, p.options, p.votes, p.voters, p.author, p.community_id " +
                    "FROM polls p JOIN communities c ON p.community_id = c.id " +
                    "WHERE c.name = ?")){
                ps.setString(1, communityName);
                ResultSet rs = ps.executeQuery();
                List<Map<String,Object>> polls = new ArrayList<>();
                while(rs.next()){
                    Map<String,Object> poll = new HashMap<>();
                    poll.put("id", rs.getInt("id"));
                    poll.put("question", rs.getString("question"));
                    poll.put("options", rs.getString("options"));
                    poll.put("votes", rs.getString("votes"));
                    poll.put("voters", rs.getString("voters"));
                    poll.put("author", rs.getString("author"));
                    polls.add(poll);
                }
                return gson.toJson(polls);
            }catch(SQLException e){
                System.err.println("Error fetching polls: " + e.getMessage());
                return gson.toJson(new ArrayList<>());
            }
        });

        // GET POST COMMENTS
        get("/api/post/:id/comments",(req,res)->{
            res.type("application/json");
            int postId = Integer.parseInt(req.params(":id"));
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT id, author, content, created_at, edited, edited_at FROM comments " +
                    "WHERE post_id = ? ORDER BY created_at ASC")){
                ps.setInt(1, postId);
                ResultSet rs = ps.executeQuery();
                List<Map<String,Object>> comments = new ArrayList<>();
                while(rs.next()){
                    Map<String,Object> comment = new HashMap<>();
                    comment.put("id", rs.getInt("id"));
                    comment.put("author", rs.getString("author"));
                    comment.put("comment", rs.getString("content"));
                    comment.put("timestamp", rs.getString("created_at"));
                    comment.put("edited", rs.getInt("edited"));
                    comment.put("edited_at", rs.getString("edited_at"));
                    comments.add(comment);
                }
                return gson.toJson(comments);
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // CREATE POST
        post("/api/community/:name/post",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String username = session.attribute("username");
            String communityName = req.params(":name");

            // Set multipart config for file upload
            req.raw().setAttribute("org.eclipse.jetty.multipartConfig", new MultipartConfigElement("/temp"));

            String content = null;
            String mediaBase64 = null;

            try {
                // Get content from multipart form
                Part contentPart = req.raw().getPart("content");
                if(contentPart != null){
                    InputStream contentStream = contentPart.getInputStream();
                    content = new String(contentStream.readAllBytes());
                }

                // Get media file if present
                Part mediaPart = req.raw().getPart("media");
                if(mediaPart != null && mediaPart.getSize() > 0){
                    InputStream mediaStream = mediaPart.getInputStream();
                    byte[] mediaBytes = mediaStream.readAllBytes();
                    String mimeType = mediaPart.getContentType();
                    mediaBase64 = "data:" + mimeType + ";base64," + Base64.getEncoder().encodeToString(mediaBytes);
                }
            } catch (Exception e) {
                // Fallback to regular form parameters if multipart fails
                content = req.queryParams("content");
                mediaBase64 = req.queryParams("media");
            }

            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO posts (community_id, username, content, media, likes) " +
                    "SELECT c.id, ?, ?, ?, '' FROM communities c WHERE c.name = ?")){
                ps.setString(1, username);
                ps.setString(2, content);
                ps.setString(3, mediaBase64);
                ps.setString(4, communityName);
                ps.executeUpdate();
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // CREATE COMMENT
        post("/api/post/:id/comment",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String username = session.attribute("username");
            int postId = Integer.parseInt(req.params(":id"));
            String comment = req.queryParams("comment");

            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO comments (post_id, author, content) VALUES (?, ?, ?)")){
                ps.setInt(1, postId);
                ps.setString(2, username);
                ps.setString(3, comment);
                ps.executeUpdate();
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // DELETE COMMENT
        delete("/api/comment/:id",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            int commentId = Integer.parseInt(req.params(":id"));

            try(Connection conn = connect();
                PreparedStatement getComment = conn.prepareStatement(
                    "SELECT c.author, p.community_id, m.role FROM comments c " +
                    "JOIN posts p ON c.post_id = p.id " +
                    "LEFT JOIN members m ON m.username = ? AND m.community_id = p.community_id " +
                    "WHERE c.id = ?");
                PreparedStatement deleteComment = conn.prepareStatement("DELETE FROM comments WHERE id = ?")){

                getComment.setString(1, currentUser);
                getComment.setInt(2, commentId);
                ResultSet rs = getComment.executeQuery();

                if(rs.next()){
                    String commentAuthor = rs.getString("author");
                    String userRole = rs.getString("role");

                    // Allow deletion if user is the author, owner, or admin
                    if(currentUser.equals(commentAuthor) || "owner".equals(userRole) || "admin".equals(userRole)){
                        deleteComment.setInt(1, commentId);
                        deleteComment.executeUpdate();
                        return gson.toJson(Map.of("success", true));
                    }else{
                        res.status(403);
                        return gson.toJson(Map.of("error", "Permission denied"));
                    }
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "Comment not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // UPDATE COMMENT
        post("/api/comment/:id/update",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            int commentId = Integer.parseInt(req.params(":id"));
            String newComment = req.queryParams("comment");

            try(Connection conn = connect();
                PreparedStatement getComment = conn.prepareStatement(
                    "SELECT author FROM comments WHERE id = ?");
                PreparedStatement updateComment = conn.prepareStatement(
                    "UPDATE comments SET content = ?, edited = 1, edited_at = CURRENT_TIMESTAMP WHERE id = ?")){

                getComment.setInt(1, commentId);
                ResultSet rs = getComment.executeQuery();

                if(rs.next()){
                    String commentAuthor = rs.getString("author");

                    // Only author can edit their comment
                    if(currentUser.equals(commentAuthor)){
                        updateComment.setString(1, newComment);
                        updateComment.setInt(2, commentId);
                        updateComment.executeUpdate();
                        return gson.toJson(Map.of("success", true));
                    }else{
                        res.status(403);
                        return gson.toJson(Map.of("error", "Only comment author can edit"));
                    }
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "Comment not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // LIKE/UNLIKE POST (Toggle)
        post("/api/post/:id/like",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String username = session.attribute("username");
            int postId = Integer.parseInt(req.params(":id"));

            try(Connection conn = connect();
                PreparedStatement select = conn.prepareStatement("SELECT likes FROM posts WHERE id = ?");
                PreparedStatement update = conn.prepareStatement("UPDATE posts SET likes = ? WHERE id = ?")){
                select.setInt(1, postId);
                ResultSet rs = select.executeQuery();
                if(rs.next()){
                    String likes = rs.getString("likes");
                    String newLikes = "";

                    if(likes == null || likes.isEmpty()){
                        // No likes yet, add user
                        newLikes = username;
                    }else{
                        // Check if user already liked
                        List<String> likesList = new ArrayList<>(Arrays.asList(likes.split(",")));
                        if(likesList.contains(username)){
                            // User already liked, remove (unlike)
                            likesList.remove(username);
                            newLikes = String.join(",", likesList);
                        }else{
                            // User hasn't liked, add like
                            likesList.add(username);
                            newLikes = String.join(",", likesList);
                        }
                    }

                    update.setString(1, newLikes);
                    update.setInt(2, postId);
                    update.executeUpdate();
                }
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // CREATE POLL
        post("/api/community/:name/poll",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String username = session.attribute("username");
            String communityName = req.params(":name");
            String question = req.queryParams("question");
            String options = req.queryParams("options");

            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO polls (community, community_id, question, options, votes, author) " +
                    "SELECT c.name, c.id, ?, ?, '', ? FROM communities c WHERE c.name = ?")){
                ps.setString(1, question);
                ps.setString(2, options);
                ps.setString(3, username);
                ps.setString(4, communityName);
                ps.executeUpdate();
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // ASSIGN ADMIN ROLE
        post("/api/community/:name/member/:username/assign-admin",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String communityName = req.params(":name");
            String targetUsername = req.params(":username");

            try(Connection conn = connect();
                PreparedStatement checkRole = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement updateRole = conn.prepareStatement(
                    "UPDATE members SET role = 'admin' " +
                    "WHERE username = ? AND community_id = (SELECT id FROM communities WHERE name = ?)")){

                // Check if current user is owner
                checkRole.setString(1, communityName);
                checkRole.setString(2, currentUser);
                ResultSet rs = checkRole.executeQuery();
                if(rs.next() && "owner".equals(rs.getString("role"))){
                    // Update target user to admin
                    updateRole.setString(1, targetUsername);
                    updateRole.setString(2, communityName);
                    updateRole.executeUpdate();
                    return gson.toJson(Map.of("success", true));
                }else{
                    res.status(403);
                    return gson.toJson(Map.of("error", "Only owners can assign admin roles"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // DEMOTE ADMIN TO MEMBER
        post("/api/community/:name/member/:username/demote-admin",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String communityName = req.params(":name");
            String targetUsername = req.params(":username");

            try(Connection conn = connect();
                PreparedStatement checkRole = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement updateRole = conn.prepareStatement(
                    "UPDATE members SET role = 'member' " +
                    "WHERE username = ? AND community_id = (SELECT id FROM communities WHERE name = ?)")){

                // Check if current user is owner
                checkRole.setString(1, communityName);
                checkRole.setString(2, currentUser);
                ResultSet rs = checkRole.executeQuery();
                if(rs.next() && "owner".equals(rs.getString("role"))){
                    // Update target user to member
                    updateRole.setString(1, targetUsername);
                    updateRole.setString(2, communityName);
                    updateRole.executeUpdate();
                    return gson.toJson(Map.of("success", true));
                }else{
                    res.status(403);
                    return gson.toJson(Map.of("error", "Only owners can demote admins"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // REMOVE MEMBER FROM COMMUNITY
        post("/api/community/:name/member/:username/remove",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String communityName = req.params(":name");
            String targetUsername = req.params(":username");

            try(Connection conn = connect();
                PreparedStatement checkCurrentRole = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement checkTargetRole = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement removeMember = conn.prepareStatement(
                    "DELETE FROM members WHERE username = ? AND community_id = " +
                    "(SELECT id FROM communities WHERE name = ?)")){

                // Check current user's role
                checkCurrentRole.setString(1, communityName);
                checkCurrentRole.setString(2, currentUser);
                ResultSet currentRs = checkCurrentRole.executeQuery();
                if(!currentRs.next()){
                    res.status(403);
                    return gson.toJson(Map.of("error", "You are not a member of this community"));
                }
                String currentRole = currentRs.getString("role");

                // Check target user's role
                checkTargetRole.setString(1, communityName);
                checkTargetRole.setString(2, targetUsername);
                ResultSet targetRs = checkTargetRole.executeQuery();
                if(!targetRs.next()){
                    res.status(404);
                    return gson.toJson(Map.of("error", "Target user is not a member"));
                }
                String targetRole = targetRs.getString("role");

                // Prevent removing owner
                if("owner".equals(targetRole)){
                    res.status(403);
                    return gson.toJson(Map.of("error", "Cannot remove the owner from the community"));
                }

                // Owner can remove anyone (except owner which is already checked)
                // Admin can remove members but not other admins or owner
                if("owner".equals(currentRole)){
                    removeMember.setString(1, targetUsername);
                    removeMember.setString(2, communityName);
                    removeMember.executeUpdate();
                    return gson.toJson(Map.of("success", true));
                }else if("admin".equals(currentRole) && "member".equals(targetRole)){
                    removeMember.setString(1, targetUsername);
                    removeMember.setString(2, communityName);
                    removeMember.executeUpdate();
                    return gson.toJson(Map.of("success", true));
                }else{
                    res.status(403);
                    return gson.toJson(Map.of("error", "You don't have permission to remove this member"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // VOTE ON POLL (Toggle vote - vote or unvote)
        post("/api/poll/:id/vote",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String username = session.attribute("username");
            int pollId = Integer.parseInt(req.params(":id"));
            int optionIndex = Integer.parseInt(req.queryParams("option"));

            try(Connection conn = connect();
                PreparedStatement select = conn.prepareStatement(
                    "SELECT votes, voters FROM polls WHERE id = ?");
                PreparedStatement update = conn.prepareStatement(
                    "UPDATE polls SET votes = ?, voters = ? WHERE id = ?")){
                select.setInt(1, pollId);
                ResultSet rs = select.executeQuery();
                if(rs.next()){
                    String voters = rs.getString("voters");
                    if(voters == null) voters = "";
                    String votes = rs.getString("votes");
                    if(votes == null || votes.isEmpty()) votes = "0,0,0,0";
                    String[] voteArray = votes.split(",");

                    // Store as "username:optionIndex"
                    String userVote = username + ":" + optionIndex;

                    // Check if user already voted on ANY option
                    String[] voterList = voters.isEmpty() ? new String[0] : voters.split(",");
                    int previousVoteIndex = -1;
                    List<String> updatedVoters = new ArrayList<>();

                    for(String voter : voterList){
                        if(voter.startsWith(username + ":")){
                            // User already voted, extract which option
                            String[] parts = voter.split(":");
                            if(parts.length == 2){
                                previousVoteIndex = Integer.parseInt(parts[1]);
                                // If clicking same option, unvote
                                if(previousVoteIndex == optionIndex){
                                    // Decrement the vote count
                                    int currentVotes = Integer.parseInt(voteArray[optionIndex]);
                                    if(currentVotes > 0){
                                        voteArray[optionIndex] = String.valueOf(currentVotes - 1);
                                    }
                                    String newVotes = String.join(",", voteArray);
                                    String newVoters = String.join(",", updatedVoters);

                                    update.setString(1, newVotes);
                                    update.setString(2, newVoters);
                                    update.setInt(3, pollId);
                                    update.executeUpdate();
                                    return gson.toJson(Map.of("success", true, "action", "unvoted"));
                                }
                                // Don't add the old vote to updated list (we'll change it)
                            }
                        }else{
                            updatedVoters.add(voter);
                        }
                    }

                    // If user voted on a different option, prevent it
                    if(previousVoteIndex != -1 && previousVoteIndex != optionIndex){
                        res.status(400);
                        return gson.toJson(Map.of("error", "You have already voted on this poll. Click your previous vote to unvote first."));
                    }

                    // User hasn't voted yet, add their vote
                    int currentVotes = Integer.parseInt(voteArray[optionIndex]);
                    voteArray[optionIndex] = String.valueOf(currentVotes + 1);
                    String newVotes = String.join(",", voteArray);

                    // Add user vote with option index
                    updatedVoters.add(userVote);
                    String newVoters = String.join(",", updatedVoters);

                    update.setString(1, newVotes);
                    update.setString(2, newVoters);
                    update.setInt(3, pollId);
                    update.executeUpdate();
                    return gson.toJson(Map.of("success", true, "action", "voted"));
                }
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // DELETE POST
        delete("/api/post/:id",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            int postId = Integer.parseInt(req.params(":id"));

            try(Connection conn = connect();
                PreparedStatement getPost = conn.prepareStatement(
                    "SELECT p.username, p.community_id, m.role FROM posts p " +
                    "LEFT JOIN members m ON m.username = ? AND m.community_id = p.community_id " +
                    "WHERE p.id = ?");
                PreparedStatement deletePost = conn.prepareStatement("DELETE FROM posts WHERE id = ?");
                PreparedStatement deleteComments = conn.prepareStatement("DELETE FROM comments WHERE post_id = ?")){

                getPost.setString(1, currentUser);
                getPost.setInt(2, postId);
                ResultSet rs = getPost.executeQuery();

                if(rs.next()){
                    String postAuthor = rs.getString("username");
                    String userRole = rs.getString("role");

                    // Allow deletion if user is the author, owner, or admin
                    if(currentUser.equals(postAuthor) || "owner".equals(userRole) || "admin".equals(userRole)){
                        deleteComments.setInt(1, postId);
                        deleteComments.executeUpdate();
                        deletePost.setInt(1, postId);
                        deletePost.executeUpdate();
                        return gson.toJson(Map.of("success", true));
                    }else{
                        res.status(403);
                        return gson.toJson(Map.of("error", "Permission denied"));
                    }
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "Post not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // DELETE POLL
        delete("/api/poll/:id",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            int pollId = Integer.parseInt(req.params(":id"));

            try(Connection conn = connect();
                PreparedStatement getPoll = conn.prepareStatement(
                    "SELECT p.author, p.community_id, m.role FROM polls p " +
                    "LEFT JOIN members m ON m.username = ? AND m.community_id = p.community_id " +
                    "WHERE p.id = ?");
                PreparedStatement deletePoll = conn.prepareStatement("DELETE FROM polls WHERE id = ?")){

                getPoll.setString(1, currentUser);
                getPoll.setInt(2, pollId);
                ResultSet rs = getPoll.executeQuery();

                if(rs.next()){
                    String pollAuthor = rs.getString("author");
                    String userRole = rs.getString("role");

                    // Allow deletion if user is the author, owner, or admin
                    if(currentUser.equals(pollAuthor) || "owner".equals(userRole) || "admin".equals(userRole)){
                        deletePoll.setInt(1, pollId);
                        deletePoll.executeUpdate();
                        return gson.toJson(Map.of("success", true));
                    }else{
                        res.status(403);
                        return gson.toJson(Map.of("error", "Permission denied"));
                    }
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "Poll not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // GET USER PROFILE
        get("/api/user/:username/profile",(req,res)->{
            res.type("application/json");
            String username = req.params(":username");
            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "SELECT username, bio, branch, semester, profile_pic FROM users WHERE username = ?")){
                ps.setString(1, username);
                ResultSet rs = ps.executeQuery();
                if(rs.next()){
                    Map<String,Object> profile = new HashMap<>();
                    profile.put("username", rs.getString("username"));
                    profile.put("bio", rs.getString("bio"));
                    profile.put("branch", rs.getString("branch"));
                    profile.put("semester", rs.getInt("semester"));
                    profile.put("profile_pic", rs.getString("profile_pic"));
                    return gson.toJson(profile);
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "User not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // UPDATE USER PROFILE
        post("/api/user/:username/profile",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String username = req.params(":username");

            // Only allow users to edit their own profile
            if(!currentUser.equals(username)){
                res.status(403);
                return gson.toJson(Map.of("error", "Permission denied"));
            }

            // Set multipart config for file upload
            req.raw().setAttribute("org.eclipse.jetty.multipartConfig", new MultipartConfigElement("/temp"));

            String bio = null;
            String branch = null;
            String semesterStr = null;
            String profilePicBase64 = null;

            try {
                // Get form data from multipart
                Part bioPart = req.raw().getPart("bio");
                if(bioPart != null){
                    bio = new String(bioPart.getInputStream().readAllBytes());
                }

                Part branchPart = req.raw().getPart("branch");
                if(branchPart != null){
                    branch = new String(branchPart.getInputStream().readAllBytes());
                }

                Part semesterPart = req.raw().getPart("semester");
                if(semesterPart != null){
                    semesterStr = new String(semesterPart.getInputStream().readAllBytes());
                }

                // Get profile picture if present
                Part profilePicPart = req.raw().getPart("profile_pic");
                if(profilePicPart != null && profilePicPart.getSize() > 0){
                    byte[] picBytes = profilePicPart.getInputStream().readAllBytes();
                    String mimeType = profilePicPart.getContentType();
                    profilePicBase64 = "data:" + mimeType + ";base64," + Base64.getEncoder().encodeToString(picBytes);
                }
            } catch (Exception e) {
                // Fallback to regular form parameters
                bio = req.queryParams("bio");
                branch = req.queryParams("branch");
                semesterStr = req.queryParams("semester");
            }

            Integer semester = (semesterStr != null && !semesterStr.isEmpty()) ? Integer.parseInt(semesterStr) : null;

            try(Connection conn = connect();
                PreparedStatement ps = conn.prepareStatement(
                    "UPDATE users SET bio = ?, branch = ?, semester = ?, profile_pic = ? WHERE username = ?")){
                ps.setString(1, bio);
                ps.setString(2, branch);
                if(semester != null){
                    ps.setInt(3, semester);
                }else{
                    ps.setNull(3, java.sql.Types.INTEGER);
                }
                ps.setString(4, profilePicBase64);
                ps.setString(5, username);
                int updated = ps.executeUpdate();
                if(updated > 0){
                    return gson.toJson(Map.of("success", true));
                }else{
                    res.status(404);
                    return gson.toJson(Map.of("error", "User not found"));
                }
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // JOIN COMMUNITY
        post("/api/community/:name/join",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String communityName = req.params(":name");

            try(Connection conn = connect();
                PreparedStatement checkMember = conn.prepareStatement(
                    "SELECT m.id FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement insertMember = conn.prepareStatement(
                    "INSERT INTO members (username, community_id, role) " +
                    "SELECT ?, c.id, 'member' FROM communities c WHERE c.name = ?")){

                // Check if already a member
                checkMember.setString(1, communityName);
                checkMember.setString(2, currentUser);
                ResultSet rs = checkMember.executeQuery();
                if(rs.next()){
                    res.status(400);
                    return gson.toJson(Map.of("error", "You are already a member of this community"));
                }

                // Add user as member
                insertMember.setString(1, currentUser);
                insertMember.setString(2, communityName);
                insertMember.executeUpdate();
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        // LEAVE COMMUNITY
        post("/api/community/:name/leave",(req,res)->{
            res.type("application/json");
            Session session = req.session(false);
            if(session == null || session.attribute("username") == null){
                res.status(401);
                return gson.toJson(Map.of("error", "Not logged in"));
            }
            String currentUser = session.attribute("username");
            String communityName = req.params(":name");

            try(Connection conn = connect();
                PreparedStatement checkRole = conn.prepareStatement(
                    "SELECT m.role FROM members m " +
                    "JOIN communities c ON m.community_id = c.id " +
                    "WHERE c.name = ? AND m.username = ?");
                PreparedStatement deleteMember = conn.prepareStatement(
                    "DELETE FROM members WHERE username = ? AND community_id = " +
                    "(SELECT id FROM communities WHERE name = ?)")){

                // Check if user is owner
                checkRole.setString(1, communityName);
                checkRole.setString(2, currentUser);
                ResultSet rs = checkRole.executeQuery();
                if(rs.next()){
                    String role = rs.getString("role");
                    if("owner".equals(role)){
                        res.status(403);
                        return gson.toJson(Map.of("error", "Owners cannot leave their community"));
                    }
                }else{
                    res.status(400);
                    return gson.toJson(Map.of("error", "You are not a member of this community"));
                }

                // Remove user from community
                deleteMember.setString(1, currentUser);
                deleteMember.setString(2, communityName);
                deleteMember.executeUpdate();
                return gson.toJson(Map.of("success", true));
            }catch(SQLException e){
                res.status(500);
                return gson.toJson(Map.of("error", e.getMessage()));
            }
        });

        System.out.println("Server running at http://localhost:4567");
    }
}
