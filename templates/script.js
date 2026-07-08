function switchTab(evt, tabId) {
    const panels = document.querySelectorAll('.content-panel');
    panels.forEach(p => p.classList.remove('active'));

    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(b => b.classList.remove('active'));

    document.getElementById(tabId).classList.add('active');
    evt.currentTarget.classList.add('active');
}

function toggleSeverityGroup(groupId) {
    const content = document.getElementById(groupId);
    const header = content.previousElementSibling;
    content.classList.toggle('active');
    header.classList.toggle('collapsed');
}
