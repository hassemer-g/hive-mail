const container = document.getElementById("menu-container");
const mainMenu = document.getElementById("main-menu");

document.addEventListener("click", async (event) => {
    const button = event.target.closest("button");
    if (!button) return;

    const menu = button.dataset.menu;
    const action = button.dataset.action;

    if (action === "return-main") {
        showMenu("main-menu");
        return;
    }

    if (menu && menu !== "main-menu") {
        const pageId = `${menu}-content`;

        showMenu(pageId);
        await import(`./${menu}.js`);

        resetPage(pageId);
        return;
    }

    if (menu === "main-menu") {
        showMenu("main-menu");
        return;
    }
});

function resetPage(pageId) {
    const page = document.getElementById(pageId);
    if (!page) return;

    page.querySelectorAll("input").forEach(input => {
        input.value = "";
        input.style.borderColor = "";
    });

    page.querySelectorAll("[id^='resultMessage']").forEach(p => {
        p.textContent = "";
    });

    page.querySelectorAll("[id*='Container']").forEach(c => {
        c.classList.remove("visible");
    });

    page.querySelectorAll("button:not([data-action='return-main'])")
        .forEach(btn => {
            btn.disabled = true;
            btn.style.backgroundColor = "";
        });
}

function showMenu(id) {

    container.querySelectorAll(".submenu").forEach(el => {
        el.classList.remove("visible");
        el.classList.add("hidden");
    });

    const target = document.getElementById(id);
    if (target) {
        target.classList.add("visible");
        target.classList.remove("hidden");
    }
}
