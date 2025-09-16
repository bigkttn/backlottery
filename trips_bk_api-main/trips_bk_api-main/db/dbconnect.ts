import sqlite3 from "sqlite3";

const db = new sqlite3.Database("./tripbooking.db", (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    } else {
        console.log("Connected to the tripbooking database.");
    }
});

export default db;