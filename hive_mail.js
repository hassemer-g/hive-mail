import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
    buildNewSaveFile,
    loadSaveFile,
} from "../[LIB-hive]/hm.js";
import {
    validateAccountNameStructure,
} from "../[LIB-hive]/sync_aux_fxs.js";

import { promptUserInputReadline } from "../[LIB]/synchronous_prompt.js";


// Convert import.meta.url to a file path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Prompt for account name
const userName = promptUserInputReadline(
    `Enter the name of your Hive account: `,
    validateAccountNameStructure,
);

// Resolve full path to the save file inside the folder
const saveDir = path.join(__dirname, userName);

// Ensure the save folder exists
if (!fs.existsSync(saveDir)) {
    fs.mkdirSync(saveDir, { recursive: true });
}

const saveFileName = "save_file.json";
const saveFilePath = path.join(saveDir, saveFileName);

// Load save file, or trigger save file creation if it is missing
if (!fs.existsSync(saveFilePath)) {
    buildNewSaveFile(userName, saveDir, saveFilePath);
} else {
    loadSaveFile(userName, saveDir, saveFilePath);
}

