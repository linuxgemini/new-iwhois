/**
 * New Generation Interactive WHOIS
 * @author linuxgemini
 * @license
 * Copyright 2020 İlteriş Yağıztegin Eroğlu (linuxgemini)
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

"use strict";

const util = require("util");
const sleep = util.promisify(setTimeout);

const WHOIS = require("./libs/whois");
const whois = new WHOIS();

const redis = require("redis");
const { RateLimiterRedis } = require("rate-limiter-flexible");

const express = require("express");

let config, redisClient, rateLimiter, rateLimiterMiddleware, app;

/**
 * @param {Error} err
 */
const exitWithError = (err) => {
    console.error("\n\nAn error occured!\n");
    if (err.stack) console.error(`\nStacktrace:\n${err.stack}\n`);
    return setTimeout(() => {
        process.exit(1);
    }, 1000);
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 */
const handleRoot = (req, res, next) => { // eslint-disable-line no-unused-vars
    res.set("Content-Type", "text/html; charset=utf-8");
    return res.status(200).send(`<!DOCTYPE html>
<html>
    <head>
        <title>linuxgemini's simple whois server</title>
    </head>
    <body>
        <h2>simple whois server</h2>
        </br>
        <p>
            hello!
            </br>example route for standard recursive whois: <a href="w/google.com">/w/google.com</a>
            </br>example route for whois for RIPE (-B flag is already added): <a href="ripe/ORG-TCA23-RIPE">/ripe/ORG-TCA23-RIPE</a>
        </p>
        </br>
        <label for="method">WHOIS Host:</label>
        <select id="method" required>
            <option value="w" onclick="document.getElementById('whoisval').placeholder='google.com'" selected>recursive</option>
            <option value="ripe" onclick="document.getElementById('whoisval').placeholder='ORG-TCA23-RIPE'">ripe</option>
            <option value="arin" onclick="document.getElementById('whoisval').placeholder='a 174'">arin</option>
            <option value="afrinic">afrinic</option>
            <option value="apnic">apnic</option>
            <option value="lacnic">lacnic</option>
            <option value="radb" onclick="document.getElementById('whoisval').placeholder='1.1.1.0/24'">radb</option>
        </select>
        <label for="whoisval">Target:</label>
        <input type="text" id="whoisval" placeholder="google.com" required>
        <input type="submit" id="postit" onclick="window.location.href=document.getElementById('method').value+'/'+document.getElementById('whoisval').value">
        </br>
        </br>
        <p>Powered by <a href="https://github.com/linuxgemini/new-iwhois">new-iwhois</a></p>
        <script>
            var node = document.getElementById("whoisval");
            node.addEventListener("keyup", function(event) {
                if (event.key === "Enter") {
                    window.location.href = document.getElementById("method").value + "/" + document.getElementById("whoisval").value;
                }
            });
        </script>
    </body>
</html>`);
};

/**
 * @param {express.Request} req
 * @param {express.Response} res
 * @param {express.NextFunction} next
 * @param {string} queryType
 */
const handleQuery = async (req, res, next, queryType) => { // eslint-disable-line no-unused-vars
    let result;
    try {
        switch (queryType) {
            case "recursive":
                result = await whois.queryRecursive(req.params["whoisValue"]);
                break;
            case "ripe":
                result = await whois.queryRIPE(req.params["whoisValue"]);
                break;
            case "arin":
                result = await whois.queryARIN(req.params["whoisValue"]);
                break;
            case "afrinic":
                result = await whois.queryAFRINIC(req.params["whoisValue"]);
                break;
            case "apnic":
                result = await whois.queryAPNIC(req.params["whoisValue"]);
                break;
            case "lacnic":
                result = await whois.queryLACNIC(req.params["whoisValue"]);
                break;
            case "radb":
                result = await whois.queryRADb(req.params["whoisValue"]);
                break;
            default:
                throw new Error("Scripting Error");
        }
    } catch (error) {
        result = error.message;
    }

    res.set("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(result);
};

const main = async () => {
    try {
        config = require("./config.json");
    } catch (e) {
        return exitWithError(new Error("Config file not found! Please check config.json.example"));
    }

    redisClient = redis.createClient(config.redisConfig);
    rateLimiter = new RateLimiterRedis({
        storeClient: redisClient,
        keyPrefix: "middleware",
        points: 4, // 2 requests
        duration: 10, // per 1 second by IP
    });

    /**
     * @param {express.Request} req
     * @param {express.Response} res
     * @param {express.NextFunction} next
     */
    rateLimiterMiddleware = (req, res, next) => {
        let reqip = req.ip;
        let xfwip = (req.headers["X-Forwarded-For"] && req.headers["X-Forwarded-For"].includes(", ") ? req.headers.forwarded.replace(/\s+/g, "").split(",")[0] : req.headers.forwarded);
        let host = (reqip !== xfwip ? xfwip : reqip);

        rateLimiter.consume(host)
            .then(() => {
                next();
            })
            .catch(() => {
                res.status(429).send("Too Many Requests");
            });
    };

    app = express();

    app.use(rateLimiterMiddleware);
    app.enable("trust proxy");
    app.disable("x-powered-by");

    app.get("/", handleRoot);
    app.get("/w/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "recursive"));
    app.get("/ripe/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "ripe"));
    app.get("/arin/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "arin"));
    app.get("/afrinic/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "afrinic"));
    app.get("/apnic/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "apnic"));
    app.get("/lacnic/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "lacnic"));
    app.get("/radb/:whoisValue*", (req, res, next) => handleQuery(req, res, next, "radb"));

    app.listen(config.port, () => {
        console.log(`Server listening at port ${config.port}`);
    });
};

main();
