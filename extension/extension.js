// QuickScript extension entry point. Activation isn't required for syntax highlighting,
// but VS Code expects the module to export these functions.
function activate() {
    console.log("QuickScript extension activated");
}

function deactivate() {}

module.exports = {
    activate,
    deactivate,
};
