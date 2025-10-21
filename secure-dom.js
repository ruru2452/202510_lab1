/**
 * 安全的 DOM 操作示例
 * 這個文件展示了如何安全地處理 DOM 操作，避免 XSS 漏洞
 */

/**
 * 使用純文本更新元素內容
 * @param {HTMLElement} element - 要更新的目標元素
 * @param {string} userInput - 使用者輸入的內容
 */
function updateAsText(element, userInput) {
    if (!element || typeof userInput !== 'string') {
        throw new Error('無效的參數');
    }
    element.textContent = userInput;
}

/**
 * 創建新的文本節點
 * @param {HTMLElement} element - 父元素
 * @param {string} userInput - 使用者輸入的內容
 */
function appendTextNode(element, userInput) {
    if (!element || typeof userInput !== 'string') {
        throw new Error('無效的參數');
    }
    const textNode = document.createTextNode(userInput);
    element.appendChild(textNode);
}

/**
 * 創建新的元素並添加文本內容
 * @param {HTMLElement} parent - 父元素
 * @param {string} tagName - 新元素的標籤名
 * @param {string} userInput - 使用者輸入的內容
 * @returns {HTMLElement} 新創建的元素
 */
function createElementWithText(parent, tagName, userInput) {
    if (!parent || !tagName || typeof userInput !== 'string') {
        throw new Error('無效的參數');
    }
    const element = document.createElement(tagName);
    element.textContent = userInput;
    parent.appendChild(element);
    return element;
}

/**
 * 安全地處理 HTML 內容（需要 DOMPurify 庫）
 * @param {HTMLElement} element - 目標元素
 * @param {string} userInput - 使用者輸入的 HTML 內容
 */
function sanitizeAndSetHTML(element, userInput) {
    if (!element || typeof userInput !== 'string') {
        throw new Error('無效的參數');
    }
    if (typeof DOMPurify === 'undefined') {
        throw new Error('DOMPurify 未載入');
    }
    
    const config = {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span', 'p', 'br'],
        ALLOWED_ATTR: ['class', 'id', 'data-*'],
    };
    
    const cleanHTML = DOMPurify.sanitize(userInput, config);
    element.innerHTML = cleanHTML;
}
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
