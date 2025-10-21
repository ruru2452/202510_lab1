// 不安全的方式 - 不要這樣做
function unsafeUpdate(userInput) {
    // 危險：直接將使用者輸入插入為 HTML
    element.innerHTML = userInput;            // 有 XSS 風險
    element.outerHTML = userInput;           // 有 XSS 風險
    document.write(userInput);               // 有 XSS 風險
}

// 安全的方式
function safeUpdate(userInput) {
    // 方法 1：使用 textContent（最安全的方式）
    element.textContent = userInput;

    // 方法 2：使用 createTextNode
    const textNode = document.createTextNode(userInput);
    element.appendChild(textNode);

    // 方法 3：如果需要創建元素
    const safeDiv = document.createElement('div');
    safeDiv.textContent = userInput;
    element.appendChild(safeDiv);

    // 方法 4：如果確實需要 HTML（請謹慎使用）
    const sanitizedHTML = DOMPurify.sanitize(userInput);
    // 方法 1: 使用 textContent
    element.textContent = userInput;

    // 方法 2: 使用 DOM API
    const newElement = document.createElement('div');
    const textNode = document.createTextNode(userInput);
    newElement.appendChild(textNode);

    // 方法 3: HTML 轉義函數
    function escapeHtml(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
}
