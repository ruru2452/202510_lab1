/**
 * @fileoverview 安全的 DOM 操作工具庫
 * 提供一套安全的 DOM 操作方法，防止 XSS 攻擊
 * @version 1.0.0
 */

/**
 * DOM 安全操作的配置選項
 * @type {Object}
 */
const SecurityConfig = {
    // 允許的 HTML 標籤白名單
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'span', 'p', 'br', 'div', 'a'],
    // 允許的 HTML 屬性白名單
    ALLOWED_ATTR: ['class', 'id', 'data-*', 'href', 'target', 'rel'],
    // URL 白名單模式
    URL_PATTERN: /^(?:https?:\/\/)?[\w.-]+\.[a-zA-Z]{2,}(?:\/[\w.-]*)*\/?$/,
    // 最大內容長度（字符）
    MAX_CONTENT_LENGTH: 5000
};

/**
 * 驗證工具類
 * @type {Object}
 */
const Validator = {
    /**
     * 驗證 DOM 元素
     * @param {HTMLElement} element - 要驗證的元素
     * @throws {Error} 如果元素無效
     */
    validateElement(element) {
        if (!(element instanceof HTMLElement)) {
            throw new TypeError('無效的 DOM 元素');
        }
    },

    /**
     * 驗證字符串輸入
     * @param {string} input - 要驗證的字符串
     * @throws {Error} 如果輸入無效或超出長度限制
     */
    validateInput(input) {
        if (typeof input !== 'string') {
            throw new TypeError('輸入必須是字符串');
        }
        if (input.length > SecurityConfig.MAX_CONTENT_LENGTH) {
            throw new Error(`內容長度超過限制 ${SecurityConfig.MAX_CONTENT_LENGTH} 字符`);
        }
    },

    /**
     * 驗證 URL
     * @param {string} url - 要驗證的 URL
     * @returns {boolean} URL 是否有效
     */
    isValidUrl(url) {
        return SecurityConfig.URL_PATTERN.test(url);
    }
};

/**
 * 日誌記錄器
 * @type {Object}
 */
const Logger = {
    /**
     * 記錄安全相關事件
     * @param {string} action - 操作類型
     * @param {Object} details - 詳細信息
     */
    logSecurityEvent(action, details) {
        console.warn(`安全事件: ${action}`, details);
        // 這裡可以添加更多日誌記錄邏輯，如發送到服務器
    }
};

/**
 * 安全地更新元素的文本內容
 * @param {HTMLElement} element - 目標元素
 * @param {string} content - 要設置的內容
 * @throws {Error} 如果參數無效
 */
function setTextContent(element, content) {
    try {
        Validator.validateElement(element);
        Validator.validateInput(content);
        element.textContent = content;
    } catch (error) {
        Logger.logSecurityEvent('setText-error', { error: error.message });
        throw error;
    }
}

/**
 * 安全地創建文本節點
 * @param {HTMLElement} parent - 父元素
 * @param {string} content - 文本內容
 * @returns {Text} 新創建的文本節點
 */
function createSafeTextNode(parent, content) {
    try {
        Validator.validateElement(parent);
        Validator.validateInput(content);
        const textNode = document.createTextNode(content);
        parent.appendChild(textNode);
        return textNode;
    } catch (error) {
        Logger.logSecurityEvent('createTextNode-error', { error: error.message });
        throw error;
    }
}

/**
 * 安全地創建元素
 * @param {HTMLElement} parent - 父元素
 * @param {string} tagName - 標籤名稱
 * @param {Object} options - 配置選項
 * @param {string} [options.text] - 文本內容
 * @param {Object} [options.attributes] - 元素屬性
 * @returns {HTMLElement} 新創建的元素
 */
function createElement(parent, tagName, options = {}) {
    try {
        Validator.validateElement(parent);
        if (typeof tagName !== 'string' || !SecurityConfig.ALLOWED_TAGS.includes(tagName.toLowerCase())) {
            throw new Error('不允許的 HTML 標籤');
        }

        const element = document.createElement(tagName);

        if (options.text) {
            Validator.validateInput(options.text);
            element.textContent = options.text;
        }

        if (options.attributes) {
            Object.entries(options.attributes).forEach(([key, value]) => {
                if (SecurityConfig.ALLOWED_ATTR.includes(key)) {
                    if (key === 'href' && !Validator.isValidUrl(value)) {
                        Logger.logSecurityEvent('invalid-url', { url: value });
                        return;
                    }
                    element.setAttribute(key, value);
                }
            });
        }

        parent.appendChild(element);
        return element;
    } catch (error) {
        Logger.logSecurityEvent('createElement-error', { error: error.message });
        throw error;
    }
}

/**
 * 使用 DOMPurify 安全地設置 HTML 內容
 * @param {HTMLElement} element - 目標元素
 * @param {string} html - HTML 內容
 */
function setSanitizedHTML(element, html) {
    try {
        Validator.validateElement(element);
        Validator.validateInput(html);

        if (typeof DOMPurify === 'undefined') {
            throw new Error('DOMPurify 未載入');
        }

        const cleanHTML = DOMPurify.sanitize(html, {
            ALLOWED_TAGS: SecurityConfig.ALLOWED_TAGS,
            ALLOWED_ATTR: SecurityConfig.ALLOWED_ATTR,
            RETURN_DOM_FRAGMENT: false,
            SANITIZE_DOM: true
        });

        // 在設置 innerHTML 之前記錄潛在的風險
        if (cleanHTML !== html) {
            Logger.logSecurityEvent('content-sanitized', {
                original: html,
                sanitized: cleanHTML
            });
        }

        element.innerHTML = cleanHTML;
    } catch (error) {
        Logger.logSecurityEvent('setHTML-error', { error: error.message });
        throw error;
    }
    }


/**
 * HTML 轉義函數
 * @param {string} str - 要轉義的字符串
 * @returns {string} 轉義後的字符串
 */
function escapeHtml(str) {
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
