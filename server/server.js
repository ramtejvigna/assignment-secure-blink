import express from "express";
import cors from "cors";
import morgan from "morgan";
import dotenv from "dotenv";
import rateLimit from "express-rate-limit";
import { body, validationResult } from "express-validator";
import { spawn } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


dotenv.config();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const corsOptions = {
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(",") : ["*"],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}

app.use(cors(corsOptions));

let loggerOption = "dev";

if(process.env.NODE_ENV === "development") {
    loggerOption = "dev";
} else {
    loggerOption = "combined";
}

app.use(morgan(loggerOption));

const limit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: "Too many requests, please try again later.",
    standardHeaders: true,
    legacyHeaders: false,
})

app.use(limit);


const validateDomain = [
    body('domain')
        .isLength({ min: 1 })
        .withMessage("Domain is required")
        .matches(/^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/)
        .withMessage("Invalid domain format"),

    body('timeout')
        .optional()
        .isInt({ min: 30, max: 300 })
        .withMessage("Timeout must be between 30 and 300 seconds"),

    body('workers')
        .optional()
        .isInt({ min: 1, max: 30 })
        .withMessage("Workers must be between 1 and 30")
]

async function ensureDirectoryExists(dirPath) {
    if(!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
    }
    return dirPath;
}

async function executeScript(domain, resultsDir, timeout, workers, verbose, jsonOnly, csvOnly) {
    return new Promise((resolve, reject) => {
        const args = [
            process.env.PYTHON_PATH || path.join(__dirname, '../scripts/main.py'),
            domain,
            '--output-dir', resultsDir,
            '--timeout', timeout || 300,
            '--workers', workers || 20,
            verbose ? "--verbose" : "",
            jsonOnly ? "--json-only" : "",
            csvOnly ? "--csv-only" : "",
        ].filter(arg => arg !== "");

        // Try python3 first, then fallback to python
        let pythonCmd = 'python3';
        const pythonProcess = spawn(pythonCmd, args);
        
        pythonProcess.on('error', (error) => {
            if (error.code === 'ENOENT') {
                pythonCmd = 'python';
                const fallbackProcess = spawn(pythonCmd, args);
                handlePythonProcess(fallbackProcess, resolve, reject);
            } else {
                reject(new Error(`Error executing script: ${error.message}`));
            }
        });
        
        handlePythonProcess(pythonProcess, resolve, reject);
    });
}

function handlePythonProcess(pythonProcess, resolve, reject) {
    let stdout = "";
    let stderr = "";

    pythonProcess.stdout.on("data", (data) => {
        stdout += data.toString();
    });

    pythonProcess.stderr.on("data", (data) => {
        stderr += data.toString();
    });

    pythonProcess.on("close", (code) => {
        console.log(`Python script exited with code: ${code}`);
        console.log("Python script stdout:", stdout);
        console.log("Python script stderr:", stderr);
        
        if(code === 0) {
            resolve({
                success: true,
                message: "Reconnaissance completed successfully",
                output: stdout,
            })
        } else {
            reject(new Error(`Script exited with code ${code}\nSTDOUT: ${stdout}\nSTDERR: ${stderr}`));
        }
    });

    pythonProcess.on("error", (error) => {
        reject(new Error(`Error executing script: ${error.message}`));
    })
}

function readResults(resultsDir, domain, format) {
    const filename = format === 'json' ? 
        `${domain}_reconnaissance_report.json` : 
        `${domain}_subdomains.csv`;
    
    const filePath = path.join(resultsDir, filename);
    
    try {
        const data = fs.readFileSync(filePath, 'utf-8');
        return format === 'json' ? JSON.parse(data) : data;
    } catch (error) {
        throw new Error(`Failed to read results file: ${error.message}`);
    }
}

app.get("/", (req, res) => {
    res.send("Hi, Welcome to the Reconnaissance API server");
})


app.post('/api/reconnaissance', validateDomain, async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            errors: errors.array()
        })
    }

    const {
        domain,
        timeout,
        workers,
        verbose,
        jsonOnly, csvOnly
    } = req.body;

    try {
        const resultsDir = await ensureDirectoryExists(path.join(__dirname, "results", domain));
        
        const startTime = Date.now();

        const scriptResult = await executeScript(domain, resultsDir, timeout, workers, verbose, jsonOnly, csvOnly);

        const executionTime = (Date.now() - startTime) / 1000;

        // Check if results file exists before trying to read it
        const resultsFilePath = path.join(resultsDir, `${domain}_reconnaissance_report.json`);
        
        let resultsData = {};
        try {
            await fs.promises.access(resultsFilePath);
            resultsData = readResults(resultsDir, domain, 'json');
        } catch (fileError) {
            // If file doesn't exist, try to parse results from script output
            console.log("Results file not found, trying to parse from script output");
            try {
                resultsData = JSON.parse(scriptResult.output);
            } catch (parseError) {
                console.error("Could not parse script output as JSON:", parseError);
                resultsData = {
                    domain: domain,
                    timestamp: new Date().toISOString(),
                    total_subdomains: 0,
                    active_subdomains: 0,
                    subdomains: [],
                    active_hosts: [],
                    errors: [`Failed to create results file: ${fileError.message}`]
                };
            }
        }

        return res.json({
            success: true,
            message: "Reconnaissance completed successfully",
            executionTime,
            results: resultsData,
        })
    } catch (error) {
        console.error("Error in reconnaissance:", error);
        return res.status(500).json({
            success: false,
            message: "Internal server error",
            error: error.message,
            details: error.output ? error.output.toString() : "No additional details available"
        })
    }
})

app.get('/api/results/:domain', async (req, res) => {
    const { domain } = req.params;
    const { format = 'json' } = req.query;

    // Validate domain parameter
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid domain format'
        });
    }

    try {
        const resultsDir = path.join(__dirname, "results", domain);
        const resultsData = readResults(resultsDir, domain, format);
        
        if (format === 'json') {
            res.json({
                success: true,
                data: resultsData,
                metadata: {
                    domain: domain,
                    format: format,
                    timestamp: new Date().toISOString()
                }
            });
        } else {
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="${domain}_subdomains.csv"`);
            res.send(resultsData);
        }
    } catch (error) {
        res.status(404).json({
            success: false,
            error: 'Results not found',
            message: error.message
        });
    }
});

app.get('/api/results/:domain/download', async (req, res) => {
    const { domain } = req.params;
    const { format = 'json' } = req.query;

    // Validate domain parameter
    if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(domain)) {
        return res.status(400).json({
            success: false,
            error: 'Invalid domain format'
        });
    }

    const filename = format === 'json' ? 
        `${domain}_reconnaissance_report.json` : 
        `${domain}_subdomains.csv`;
    
    const filePath = path.join(__dirname, "results", domain, filename);

    try {
        await fs.promises.access(filePath);
        
        const contentType = format === 'json' ? 'application/json' : 'text/csv';
        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        
        res.download(filePath, filename);
    } catch (error) {
        res.status(404).json({
            success: false,
            error: 'File not found',
            message: `Results file for domain ${domain} not found`
        });
    }
});

app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: "Not found",
        message: "The requested resource was not found"
    })
})

app.listen(process.env.PORT || 3000, () => {
    console.log(`Server is running on http://localhost:${process.env.PORT || 3000}`);
}) 