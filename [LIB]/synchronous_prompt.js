import readlineSync from "readline-sync";


// ==================================================================== //


// Function to prompt user for input with optional validation (using readlineSync)
export function promptUserInputReadline(
    promptMessage,
    validationFunction,
    hide = false,
    maskType = null,
    repeatInput = 0, // 0 no repetition, 1 repetition required only if non-empty input, 2 repetition always required
    mustBeDifferentTo = null, // an array of strings
) {

    const options = { hideEchoBack: hide };

    // Apply maskType logic
    if (maskType !== null) {
        options.mask = maskType;
    }

    do {
        const input = readlineSync.question(promptMessage, options).trim();

        // Run regular validation
        if (!validationFunction(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        // Check against all values in mustBeDifferentTo array, if provided
        if (Array.isArray(mustBeDifferentTo) && mustBeDifferentTo.includes(input)) {
            console.error(`
    Invalid input! Try again.
            `);
            continue;
        }

        // Determine whether confirmation is needed
        const needsConfirmation = (
            repeatInput === 2
            || (repeatInput === 1 && input !== "")
        );

        // If needsConfirmation is true, ask for confirmation
        if (needsConfirmation) {

            const confirmInput = readlineSync.question(`Confirm (enter again): `, options).trim();

            if (input !== confirmInput) {
                console.error(`Error: Inputs do not match. Try again.`);
                continue; // Restart loop if inputs do not match
            }
        }

        return input;

    } while (true);

}



