import express from "express";
import cors from "cors";
import { router as index } from "./controller/index";
import { router as trip } from "./controller/trip";
import { router as ping } from "./controller/ping";
import { router as upload } from "./controller/upload";
import bodyParser from "body-parser";

export const app = express();

app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);



app.use(bodyParser.text());
app.use(bodyParser.json());
app.use("/", index);
app.use("/trip", trip);
app.use("/ping", ping);
app.use("/upload", upload);
app.use("/uploads", express.static("uploads"));