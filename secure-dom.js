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
 * 日誌嚴重程度等級
 * @readonly
 * @enum {string}
 */
const LogSeverity = {
    INFO: 'INFO',
    WARN: 'WARN',
    ERROR: 'ERROR',
    SECURITY: 'SECURITY'
};

/**
 * 預定義的日誌事件類型
 * @readonly
 * @enum {string}
 */
const LogEventType = {
    VALIDATION_ERROR: 'VALIDATION_ERROR',
    SANITIZATION: 'CONTENT_SANITIZATION',
    XSS_ATTEMPT: 'XSS_ATTEMPT',
    DOM_MANIPULATION: 'DOM_MANIPULATION',
    API_ERROR: 'API_ERROR'
};

/**
 * 安全的日誌記錄器
 * @type {Object}
 */
const Logger = {
    /**
     * 格式化日誌消息
     * @private
     * @param {LogSeverity} severity - 日誌嚴重程度
     * @param {LogEventType} eventType - 事件類型
     * @param {Object} data - 日誌數據
     * @returns {Object} 格式化的日誌對象
     */
    _formatLogMessage(severity, eventType, data) {
        return {
            timestamp: new Date().toISOString(),
            severity,
            eventType,
            data: this._sanitizeLogData(data),
            sessionId: this._getSessionId()
        };
    },

    /**
     * 淨化日誌數據
     * @private
     * @param {Object} data - 原始數據
     * @returns {Object} 淨化後的數據
     */
    _sanitizeLogData(data) {
        if (!data) return {};

        // 深度克隆以避免修改原始數據
        const sanitized = JSON.parse(JSON.stringify(data));

        // 移除敏感信息
        const sensitiveKeys = ['password', 'token', 'secret', 'key'];
        this._recursivelyRemoveSensitive(sanitized, sensitiveKeys);

        // 截斷長字符串
        this._recursivelyTruncateStrings(sanitized, 1000);

        return sanitized;
    },

    /**
     * 遞迴移除敏感數據
     * @private
     * @param {Object} obj - 要處理的對象
     * @param {string[]} sensitiveKeys - 敏感鍵名列表
     */
    _recursivelyRemoveSensitive(obj, sensitiveKeys) {
        if (typeof obj !== 'object' || obj === null) return;

        for (const key in obj) {
            if (sensitiveKeys.includes(key.toLowerCase())) {
                obj[key] = '[REDACTED]';
            } else if (typeof obj[key] === 'object') {
                this._recursivelyRemoveSensitive(obj[key], sensitiveKeys);
            }
        }
    },

    /**
     * 遞迴截斷長字符串
     * @private
     * @param {Object} obj - 要處理的對象
     * @param {number} maxLength - 最大長度
     */
    _recursivelyTruncateStrings(obj, maxLength) {
        if (typeof obj !== 'object' || obj === null) return;

        for (const key in obj) {
            if (typeof obj[key] === 'string' && obj[key].length > maxLength) {
                obj[key] = obj[key].substring(0, maxLength) + '...';
            } else if (typeof obj[key] === 'object') {
                this._recursivelyTruncateStrings(obj[key], maxLength);
            }
        }
    },

    /**
     * 獲取會話 ID
     * @private
     * @returns {string} 會話 ID
     */
    _getSessionId() {
        if (!window._logSessionId) {
            window._logSessionId = Math.random().toString(36).substring(2, 15);
        }
        return window._logSessionId;
    },

    /**
     * 記錄安全相關事件
     * @param {LogEventType} eventType - 事件類型
     * @param {Object} details - 詳細信息
     */
    logSecurityEvent(eventType, details) {
        if (!Object.values(LogEventType).includes(eventType)) {
            eventType = LogEventType.SECURITY;
        }

        const logMessage = this._formatLogMessage(
            LogSeverity.SECURITY,
            eventType,
            details
        );

        // 使用安全的日誌格式
        console.warn('%s: %s', 
            'Security Event',
            JSON.stringify(logMessage, null, 2)
        );

        // 可以添加將日誌發送到服務器的邏輯
        this._sendToLogServer(logMessage);
    },

    /**
     * 發送日誌到服務器
     * @private
     * @param {Object} logMessage - 日誌消息
     */
    _sendToLogServer(logMessage) {
        // 這裡實現發送日誌到服務器的邏輯
        // 例如使用 fetch API 或 beacon API
        try {
            if (navigator.sendBeacon) {
                navigator.sendBeacon('/api/logs', JSON.stringify(logMessage));
            }
        } catch (error) {
            // 靜默失敗 - 不在日誌中記錄日誌錯誤
        }
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

        // 使用 DOMPurify 淨化 HTML 並返回 DocumentFragment
        const cleanFragment = DOMPurify.sanitize(html, {
            ALLOWED_TAGS: SecurityConfig.ALLOWED_TAGS,
            ALLOWED_ATTR: SecurityConfig.ALLOWED_ATTR,
            RETURN_DOM_FRAGMENT: true, // 返回 DocumentFragment 而不是字串
            SANITIZE_DOM: true,
            USE_PROFILES: {
                html: true,
                svg: false,
                svgFilters: false,
                mathMl: false
            },
            FORBID_CONTENTS: ['form', 'input', 'script', 'style', 'textarea', 'iframe'],
            FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed', 'form'],
            FORBID_ATTR: ['on*', 'style', 'href', 'src']
        });

        // 記錄潛在的內容修改
        const sanitizedHTML = DOMPurify.sanitize(html, {
            ALLOWED_TAGS: SecurityConfig.ALLOWED_TAGS,
            ALLOWED_ATTR: SecurityConfig.ALLOWED_ATTR
        });
        if (sanitizedHTML !== html) {
            Logger.logSecurityEvent('content-sanitized', {
                original: html,
                sanitized: sanitizedHTML
            });
        }

        // 清空目標元素
        while (element.firstChild) {
            element.removeChild(element.firstChild);
        }

        // 安全地將淨化後的 DocumentFragment 添加到 DOM
        element.appendChild(cleanFragment);
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

/**
 * 安全地渲染富文本內容
 * @param {HTMLElement} container - 容器元素
 * @param {string} content - 要渲染的內容
 * @param {Object} options - 渲染選項
 */
function renderRichContent(container, content, options = {}) {
    try {
        // 驗證輸入
        Validator.validateElement(container);
        Validator.validateInput(content);

        // 根據內容類型選擇渲染策略
        if (options.plainText) {
            // 純文本：使用 textContent
            setTextContent(container, content);
        } else if (options.allowHtml) {
            // HTML：使用淨化和 DocumentFragment
            setSanitizedHTML(container, content);
        } else if (options.markdown) {
            // Markdown：先轉換後淨化
            const htmlContent = markdownToHtml(content);
            setSanitizedHTML(container, htmlContent);
        } else {
            // 預設：轉義 HTML
            const safeText = createSafeTextNode(container, escapeHtml(content));
            container.appendChild(safeText);
        }

        // 添加安全屬性
        if (container.tagName === 'A') {
            container.setAttribute('rel', 'noopener noreferrer');
        }

        // 記錄操作
        Logger.logSecurityEvent('content-rendered', {
            type: options.plainText ? 'text' : (options.allowHtml ? 'html' : 'escaped'),
            length: content.length
        });

    } catch (error) {
        Logger.logSecurityEvent('render-error', {
            error: error.message,
            content: content.substring(0, 100) + '...'
        });
        throw error;
    }
}

/**
 * 創建安全的互動元素
 * @param {HTMLElement} container - 容器元素
 * @param {Object} config - 元素配置
 * @returns {HTMLElement} 新創建的元素
 */
function createSecureInteractiveElement(container, config) {
    try {
        const element = createElement(container, config.tag || 'div', {
            text: config.text,
            attributes: {
                'class': config.className,
                'id': config.id,
                'data-action': config.action
            }
        });

        // 使用事件委派而不是內聯事件處理器
        if (config.onClick) {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const action = e.currentTarget.getAttribute('data-action');
                if (action && typeof config.onClick === 'function') {
                    config.onClick(e);
                }
            });
        }

        return element;
    } catch (error) {
        Logger.logSecurityEvent('create-element-error', {
            error: error.message,
            config: JSON.stringify(config)
        });
        throw error;
    }
}
