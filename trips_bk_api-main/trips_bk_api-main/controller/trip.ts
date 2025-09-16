import express, { Request, Response } from "express";
import db from "../db/dbconnect";

export interface Trip {
    idx: number;
    name: string;
    country: string;
    destinationid: number;
    coverimage: string;
    detail: string;
    price: number;
    duration: number;
}

export const router = express.Router();

// ------------------------------------------------------------
// DESTINATIONS CRUD
// ------------------------------------------------------------
// Get all destinations
router.get("/destinations", (req, res) => {
    db.all("SELECT * FROM destination", [], (err, rows) => {
        handleResponse(res, err, rows);
    });
});

// Get a specific destination
router.get("/destinations/:id", (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM destination WHERE idx = ?", [id], (err, row) => {
        handleResponse(res, err, row, 404, "Destination not found");
    });
});

// Create a new destination
router.post("/destinations", (req, res) => {
    const { zone } = req.body;
    db.run("INSERT INTO destination (zone) VALUES (?)", [zone], function (err) {
        handleResponse(
            res,
            err,
            { message: "Destination created successfully", id: this.lastID },
            500,
            "Failed to create destination"
        );
    });
});

// Update a destination
router.put("/destinations/:id", (req, res) => {
    const id = req.params.id;
    const { zone } = req.body;
    db.run(
        "UPDATE destination SET zone = ? WHERE idx = ?",
        [zone, id],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Destination updated successfully" },
                404,
                "Destination not found",
                this.changes
            );
        }
    );
});

// Delete a destination
router.delete("/destinations/:id", (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM destination WHERE idx = ?", [id], function (err) {
        handleResponse(
            res,
            err,
            { message: "Destination deleted successfully" },
            404,
            "Destination not found",
            this.changes
        );
    });
});

// ------------------------------------------------------------
// TRIPS CRUD
// ------------------------------------------------------------
// GET /trip - get all trips
router.get("/", (req, res) => {
    const sql = `
    SELECT 
        t.idx, 
        t.name, 
        t.country, 
        t.coverimage, 
        t.detail, 
        t.price, 
        t.duration,
        d.zone AS destination_zone 
    FROM 
        trip AS t
    JOIN 
        destination AS d ON t.destinationid = d.idx
    `;

    db.all(sql, [], (err, rows) => {
        handleResponse(res, err, rows);
    });
});

// GET /trip/search?name=xxx - search trips by name
router.get("/search/fields", (req: Request, res: Response) => {
    const name = req.query.name ? String(req.query.name) : "";
    if (!name.trim()) {
        return res.json([]);
    }
    const sql = "SELECT * FROM trip WHERE name LIKE ?";
    db.all(sql, [`%${name}%`], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Get a specific trip
router.get("/:id", (req, res) => {
    const id = req.params.id;
    const sql = `
    SELECT 
        t.idx, 
        t.name, 
        t.country, 
        t.coverimage, 
        t.detail, 
        t.price, 
        t.duration,
        d.zone AS destination_zone 
    FROM 
        trip AS t
    JOIN 
        destination AS d ON t.destinationid = d.idx
    WHERE 
        t.idx = ?
    `;

    db.get(sql, [id], (err, row) => {
        handleResponse(res, err, row, 404, "Trip not found");
    });
});

// Create a new trip
router.post("/", (req, res) => {
    const { name, country, destinationid, coverimage, detail, price, duration } =
        req.body;
    db.run(
        "INSERT INTO trip (name, country, destinationid, coverimage, detail, price, duration) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [name, country, destinationid, coverimage, detail, price, duration],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Trip created successfully", id: this.lastID },
                500,
                "Failed to create trip"
            );
        }
    );
});
// Update a trip
router.put("/:id", (req, res) => {
    const id = req.params.id;
    const { name, country, destinationid, coverimage, detail, price, duration } =
        req.body;
    db.run(
        "UPDATE trip SET name = ?, country = ?, destinationid = ?, coverimage = ?, detail = ?, price = ?, duration = ? WHERE idx = ?",
        [name, country, destinationid, coverimage, detail, price, duration, id],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Trip updated successfully" },
                404,
                "Trip not found",
                this.changes
            );
        }
    );
});

// Delete a trip
router.delete("/:id", (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM trip WHERE idx = ?", [id], function (err) {
        handleResponse(
            res,
            err,
            { message: "Trip deleted successfully" },
            404,
            "Trip not found",
            this.changes
        );
    });
});

// ------------------------------------------------------------
// CUSTOMERS CRUD
// ------------------------------------------------------------
// Get all customers
router.get("/customers", (req, res) => {
    db.all("SELECT * FROM customer", [], (err, rows) => {
        if (err) {
            handleResponse(res, err);
            return;
        }

        // Remove password from each customer object
        const sanitizedRows = rows.map(row => {
            const sanitizedRow = { ...rows };
            return sanitizedRow;
        });

        handleResponse(res, null, sanitizedRows);
    });
});

// Get a specific customer
router.get("/customers/:id", (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM customer WHERE idx = ?", [id], (err, row) => {
        if (err) {
            handleResponse(res, err, null, 404, "Customer not found");
            return;
        }

        if (!row) {
            handleResponse(res, null, null, 404, "Customer not found");
            return;
        }

        const sanitizedRow = { ...row };

        handleResponse(res, null, sanitizedRow);
    });
});

// Create a new customer
router.post("/customers", (req, res) => {
    const { fullname, phone, email, image, password } = req.body;
    db.run(
        "INSERT INTO customer (fullname, phone, email, image, password) VALUES (?, ?, ?, ?, ?)",
        [fullname, phone, email, image, password],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Customer created successfully", id: this.lastID },
                500,
                "Failed to create customer"
            );
        }
    );
});

// Update a customer
router.put("/customers/:id", (req, res) => {
    const id = req.params.id;
    const { fullname, phone, email, image } = req.body;
    db.run(
        "UPDATE customer SET fullname = ?, phone = ?, email = ?, image = ? WHERE idx = ?",
        [fullname, phone, email, image, id],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Customer updated successfully" },
                404,
                "Customer not found",
                this.changes
            );
        }
    );
});

// Delete a customer
router.delete("/customers/:id", (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM customer WHERE idx = ?", [id], function (err) {
        handleResponse(
            res,
            err,
            { message: "Customer deleted successfully" },
            404,
            "Customer not found",
            this.changes
        );
    });
});

router.post("/customers/login", (req, res) => {
    const { phone, password } = req.body;

    // Basic validation (you should add more robust validation in a real app)
    if (!phone || !password) {
        res.status(400).json({ error: "Phone and password are required" });
        return;
    }

    const sql = "SELECT * FROM customer WHERE phone = ? AND password = ?";
    db.get(sql, [phone, password], (err, row) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }

        if (!row) {
            res.status(401).json({ error: "Invalid phone or password" });
            return;
        }

        // Successful login - remove password from response
        const customerData = { ...row }; // Create a copy

        res.json({ message: "Login successful", customer: customerData });
    });
});

// ------------------------------------------------------------
// MEETINGS CRUD
// ------------------------------------------------------------
// Get all meetings
router.get("/meetings", (req, res) => {
    db.all("SELECT * FROM meeting", [], (err, rows) => {
        handleResponse(res, err, rows);
    });
});

// Get a specific meeting
router.get("/meetings/:id", (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM meeting WHERE idx = ?", [id], (err, row) => {
        handleResponse(res, err, row, 404, "Meeting not found");
    });
});

// Create a new meeting
router.post("/meetings", (req, res) => {
    const { detail, meetingdatetime, latitude, longitude } = req.body;
    db.run(
        "INSERT INTO meeting (detail, meetingdatetime, latitude, longitude) VALUES (?, ?, ?, ?)",
        [detail, meetingdatetime, latitude, longitude],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Meeting created successfully", id: this.lastID },
                500,
                "Failed to create meeting"
            );
        }
    );
});

// Update a meeting
router.put("/meetings/:id", (req, res) => {
    const id = req.params.id;
    const { detail, meetingdatetime, latitude, longitude } = req.body;
    db.run(
        "UPDATE meeting SET detail = ?, meetingdatetime = ?, latitude = ?, longitude = ? WHERE idx = ?",
        [detail, meetingdatetime, latitude, longitude, id],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Meeting updated successfully" },
                404,
                "Meeting not found",
                this.changes
            );
        }
    );
});

// Delete a meeting
router.delete("/meetings/:id", (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM meeting WHERE idx = ?", [id], function (err) {
        handleResponse(
            res,
            err,
            { message: "Meeting deleted successfully" },
            404,
            "Meeting not found",
            this.changes
        );
    });
});

// ------------------------------------------------------------
// BOOKINGS CRUD
// ------------------------------------------------------------
// Get all bookings
router.get("/bookings", (req, res) => {
    db.all("SELECT * FROM booking", [], (err, rows) => {
        handleResponse(res, err, rows);
    });
});

// Get a specific booking
router.get("/bookings/:id", (req, res) => {
    const id = req.params.id;
    db.get("SELECT * FROM booking WHERE idx = ?", [id], (err, row) => {
        handleResponse(res, err, row, 404, "Booking not found");
    });
});

// Create a new booking
router.post("/bookings", (req, res) => {
    const { customerid, bookdatetime, tripid, meetingid } = req.body;
    db.run(
        "INSERT INTO booking (customerid, bookdatetime, tripid, meetingid) VALUES (?, ?, ?, ?)",
        [customerid, bookdatetime, tripid, meetingid],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Booking created successfully", id: this.lastID },
                500,
                "Failed to create booking"
            );
        }
    );
});

// Update a booking
router.put("/bookings/:id", (req, res) => {
    const id = req.params.id;
    const { customerid, bookdatetime, tripid, meetingid } = req.body;
    db.run(
        "UPDATE booking SET customerid = ?, bookdatetime = ?, tripid = ?, meetingid = ? WHERE idx = ?",
        [customerid, bookdatetime, tripid, meetingid, id],
        function (err) {
            handleResponse(
                res,
                err,
                { message: "Booking updated successfully" },
                404,
                "Booking not found",
                this.changes
            );
        }
    );
});

// Delete a booking
router.delete("/bookings/:id", (req, res) => {
    const id = req.params.id;
    db.run("DELETE FROM booking WHERE idx = ?", [id], function (err) {
        handleResponse(
            res,
            err,
            { message: "Booking deleted successfully" },
            404,
            "Booking not found",
            this.changes
        );
    });
});



// Helper function to handle API responses
export function handleResponse(
    res: Response,
    err: Error | null,
    data?: any,
    notFoundStatusCode: number = 404,
    notFoundMessage: string = "Not found",
    changes: number | null = null
): void {
    if (err) {
        res.status(500).json({ error: err.message });
        return;
    }
    if (!data && !changes) {
        res.status(notFoundStatusCode).json({ error: notFoundMessage });
        return;
    }
    res.json(data);
}