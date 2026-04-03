export function protect(verifyToken) {
  return async (req, res, next) => {
    try {
      const auth = req.headers.authorization;
      if (!auth) throw new Error("No token");
      const token = auth.split(" ")[1];
      const user = await verifyToken(token);
      req.user = user;
      next();
    } catch {
      res.status(401).json({ error: "Unauthorized" });
    }
  };
}

export function routes(auth) {
  const express = require("express");
  const router = express.Router();
  router.get("/login", (req, res) => res.redirect(auth.loginUrl()));
  router.get("/callback", async (req, res) => {
    const session = await auth.handleCallback(req);
    res.json(session.user);
  });
  return router;
}

