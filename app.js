/**
 * SecurePass Generator - Password Generation Application
 * Uses CSPRNG (Web Crypto API) for secure password generation
 */

// =============================================================================
// Character Sets
// =============================================================================

const CHAR_SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
};

// Characters that look similar and can be excluded
const SIMILAR_CHARS = new Set(['i', 'l', '1', 'I', 'L', 'o', 'O', '0']);

// =============================================================================
// DOM Elements
// =============================================================================

const elements = {
    // Password display
    primaryPassword: document.getElementById('primaryPassword'),
    primaryCopyBtn: document.getElementById('primaryCopyBtn'),
    primaryPasswordContainer: document.getElementById('primaryPasswordContainer'),

    // Strength indicator
    strengthFill: document.getElementById('strengthFill'),
    strengthLabel: document.getElementById('strengthLabel'),

    // Controls
    lengthSlider: document.getElementById('lengthSlider'),
    lengthValue: document.getElementById('lengthValue'),

    // Character type toggles
    includeUppercase: document.getElementById('includeUppercase'),
    includeLowercase: document.getElementById('includeLowercase'),
    includeNumbers: document.getElementById('includeNumbers'),
    includeSymbols: document.getElementById('includeSymbols'),

    // Additional options
    excludeSimilar: document.getElementById('excludeSimilar'),

    // Password count
    passwordCountValue: document.getElementById('passwordCountValue'),
    countDecrease: document.getElementById('countDecrease'),
    countIncrease: document.getElementById('countIncrease'),

    // Buttons
    generateBtn: document.getElementById('generateBtn'),

    // Messages
    errorMessage: document.getElementById('errorMessage'),

    // Multiple passwords
    passwordsListSection: document.getElementById('passwordsListSection'),
    passwordsList: document.getElementById('passwordsList'),

    // Mobile menu
    mobileMenuBtn: document.getElementById('mobileMenuBtn'),
    mobileMenu: document.getElementById('mobileMenu'),

    // Copy popup
    copyPopupOverlay: document.getElementById('copyPopupOverlay'),
    copyPopupClose: document.getElementById('copyPopupClose'),
    popupPasswordDisplay: document.getElementById('popupPasswordDisplay'),
    copyAgainBtn: document.getElementById('copyAgainBtn'),
    generateNewBtn: document.getElementById('generateNewBtn')
};

// =============================================================================
// State
// =============================================================================

let state = {
    length: 16,
    passwordCount: 1,
    options: {
        uppercase: true,
        lowercase: true,
        numbers: true,
        symbols: true,
        excludeSimilar: false
    }
};

// =============================================================================
// Cryptographically Secure Random Generation
// =============================================================================

/**
 * Generate a cryptographically secure random integer in range [0, max)
 * Uses rejection sampling to ensure uniform distribution
 * @param {number} max - Upper bound (exclusive)
 * @returns {number} Random integer
 */
function secureRandomInt(max) {
    if (max <= 0) return 0;

    const randomBuffer = new Uint32Array(1);
    const maxValid = Math.floor(0xFFFFFFFF / max) * max;

    // Rejection sampling to avoid modulo bias
    do {
        crypto.getRandomValues(randomBuffer);
    } while (randomBuffer[0] >= maxValid);

    return randomBuffer[0] % max;
}

/**
 * Securely shuffle an array using Fisher-Yates algorithm with CSPRNG
 * @param {Array} array - Array to shuffle
 * @returns {Array} Shuffled array (mutates original)
 */
function secureShuffleArray(array) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = secureRandomInt(i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// =============================================================================
// Password Generation
// =============================================================================

/**
 * Build the character pool based on current options
 * @returns {string} Available characters for password generation
 */
function buildCharacterPool() {
    let pool = '';

    if (state.options.uppercase) pool += CHAR_SETS.uppercase;
    if (state.options.lowercase) pool += CHAR_SETS.lowercase;
    if (state.options.numbers) pool += CHAR_SETS.numbers;
    if (state.options.symbols) pool += CHAR_SETS.symbols;

    // Remove similar characters if option is enabled
    if (state.options.excludeSimilar) {
        pool = pool.split('').filter(char => !SIMILAR_CHARS.has(char)).join('');
    }

    return pool;
}

/**
 * Get one random character from each selected character set
 * Ensures the password meets complexity requirements
 * @returns {string[]} Array of guaranteed characters
 */
function getGuaranteedCharacters() {
    const guaranteed = [];

    const getRandomChar = (charset) => {
        let chars = charset;
        if (state.options.excludeSimilar) {
            chars = charset.split('').filter(c => !SIMILAR_CHARS.has(c)).join('');
        }
        if (chars.length === 0) return null;
        return chars[secureRandomInt(chars.length)];
    };

    if (state.options.uppercase) {
        const char = getRandomChar(CHAR_SETS.uppercase);
        if (char) guaranteed.push(char);
    }
    if (state.options.lowercase) {
        const char = getRandomChar(CHAR_SETS.lowercase);
        if (char) guaranteed.push(char);
    }
    if (state.options.numbers) {
        const char = getRandomChar(CHAR_SETS.numbers);
        if (char) guaranteed.push(char);
    }
    if (state.options.symbols) {
        const char = getRandomChar(CHAR_SETS.symbols);
        if (char) guaranteed.push(char);
    }

    return guaranteed;
}

/**
 * Generate a single password
 * @returns {string} Generated password
 */
function generatePassword() {
    const pool = buildCharacterPool();
    if (pool.length === 0) return '';

    // Get guaranteed characters from each selected type
    const guaranteed = getGuaranteedCharacters();

    // Fill the rest with random characters from the pool
    const remainingLength = state.length - guaranteed.length;
    const passwordChars = [...guaranteed];

    for (let i = 0; i < remainingLength; i++) {
        passwordChars.push(pool[secureRandomInt(pool.length)]);
    }

    // Shuffle to randomize positions of guaranteed characters
    secureShuffleArray(passwordChars);

    return passwordChars.join('');
}

/**
 * Generate multiple passwords
 * @param {number} count - Number of passwords to generate
 * @returns {string[]} Array of generated passwords
 */
function generateMultiplePasswords(count) {
    const passwords = [];
    for (let i = 0; i < count; i++) {
        passwords.push(generatePassword());
    }
    return passwords;
}

// =============================================================================
// Password Strength Calculation
// =============================================================================

/**
 * Calculate password entropy and strength
 * @param {string} password - Password to analyze
 * @returns {Object} Strength info with entropy, level, and label
 */
function calculateStrength(password) {
    if (!password) {
        return { entropy: 0, level: 'none', label: '--' };
    }

    // Calculate character set size
    let charsetSize = 0;
    if (/[a-z]/.test(password)) charsetSize += 26;
    if (/[A-Z]/.test(password)) charsetSize += 26;
    if (/[0-9]/.test(password)) charsetSize += 10;
    if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32; // Approximate symbols

    // Calculate entropy: log2(charset^length) = length * log2(charset)
    const entropy = password.length * Math.log2(charsetSize || 1);

    // Determine strength level based on entropy
    let level, label;

    if (entropy < 28) {
        level = 'weak';
        label = 'Weak';
    } else if (entropy < 36) {
        level = 'fair';
        label = 'Fair';
    } else if (entropy < 60) {
        level = 'good';
        label = 'Good';
    } else if (entropy < 128) {
        level = 'strong';
        label = 'Strong';
    } else {
        level = 'very-strong';
        label = 'Very Strong';
    }

    return { entropy, level, label };
}

/**
 * Update the strength indicator display
 * @param {string} password - Password to analyze
 */
function updateStrengthIndicator(password) {
    const strength = calculateStrength(password);

    // Remove all strength classes
    elements.strengthFill.className = 'strength-fill';
    elements.strengthLabel.className = 'strength-label';

    if (strength.level !== 'none') {
        elements.strengthFill.classList.add(strength.level);
        elements.strengthLabel.classList.add(strength.level);
    }

    elements.strengthLabel.textContent = strength.label;
}

// =============================================================================
// Clipboard Functions
// =============================================================================

/**
 * Copy text to clipboard with visual feedback and show popup
 * @param {string} text - Text to copy
 * @param {HTMLElement} button - Copy button element for feedback
 * @param {boolean} showPopup - Whether to show the popup (default: true)
 */
async function copyToClipboard(text, button, showPopup = true) {
    try {
        await navigator.clipboard.writeText(text);

        // Visual feedback
        button.classList.add('copied');

        // Reset after delay
        setTimeout(() => {
            button.classList.remove('copied');
        }, 2000);

        // Show popup with ad if primary copy button
        if (showPopup && button === elements.primaryCopyBtn) {
            showCopyPopup(text);
        }

    } catch (err) {
        console.error('Failed to copy to clipboard:', err);

        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();

        try {
            document.execCommand('copy');
            button.classList.add('copied');
            setTimeout(() => button.classList.remove('copied'), 2000);

            // Show popup with ad if primary copy button
            if (showPopup && button === elements.primaryCopyBtn) {
                showCopyPopup(text);
            }
        } catch (e) {
            console.error('Fallback copy failed:', e);
        }

        document.body.removeChild(textArea);
    }
}

// =============================================================================
// Copy Popup Functions
// =============================================================================

let currentPopupPassword = '';
let popupAdLoaded = false;

/**
 * Show the copy popup with ad
 * @param {string} password - The copied password to display
 */
function showCopyPopup(password) {
    currentPopupPassword = password;
    elements.popupPasswordDisplay.textContent = password;
    elements.copyPopupOverlay.classList.add('active');
    document.body.style.overflow = 'hidden';

    // Load ad dynamically only once popup is visible
    if (!popupAdLoaded) {
        loadPopupAd();
        popupAdLoaded = true;
    }
}

/**
 * Load AdSense ad in popup dynamically
 */
function loadPopupAd() {
    const adContainer = document.getElementById('popupAdContainer');
    if (!adContainer) return;

    // Create the AdSense ins element
    const adIns = document.createElement('ins');
    adIns.className = 'adsbygoogle';
    adIns.style.cssText = 'display:block; min-height:100px;';
    adIns.setAttribute('data-ad-client', 'ca-pub-8576484060734232');
    adIns.setAttribute('data-ad-slot', 'auto');
    adIns.setAttribute('data-ad-format', 'auto');
    adIns.setAttribute('data-full-width-responsive', 'true');

    adContainer.appendChild(adIns);

    // Initialize the ad after a small delay to ensure layout is stable
    setTimeout(() => {
        try {
            (window.adsbygoogle = window.adsbygoogle || []).push({});
        } catch (e) {
            console.log('AdSense loading:', e.message);
        }
    }, 100);
}

/**
 * Close the copy popup
 */
function closeCopyPopup() {
    elements.copyPopupOverlay.classList.remove('active');
    document.body.style.overflow = '';
}

/**
 * Copy password again from popup
 */
async function copyFromPopup() {
    try {
        await navigator.clipboard.writeText(currentPopupPassword);

        // Visual feedback on the button
        const btn = elements.copyAgainBtn;
        const originalText = btn.innerHTML;
        btn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M9 16.17L4.83 12L3.41 13.41L9 19L21 7L19.59 5.59L9 16.17Z" fill="currentColor"/>
            </svg>
            Copied!
        `;
        btn.style.background = 'rgba(34, 197, 94, 0.2)';
        btn.style.borderColor = 'rgba(34, 197, 94, 0.5)';

        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.style.background = '';
            btn.style.borderColor = '';
        }, 2000);
    } catch (err) {
        console.error('Failed to copy:', err);
    }
}

/**
 * Generate new password and close popup
 */
function generateFromPopup() {
    closeCopyPopup();
    handleGenerate();
}

// =============================================================================
// UI Updates
// =============================================================================

/**
 * Validate options and update UI accordingly
 * @returns {boolean} Whether options are valid
 */
function validateOptions() {
    const hasCharType = state.options.uppercase ||
        state.options.lowercase ||
        state.options.numbers ||
        state.options.symbols;

    if (!hasCharType) {
        elements.errorMessage.classList.add('visible');
        elements.generateBtn.disabled = true;
        return false;
    }

    elements.errorMessage.classList.remove('visible');
    elements.generateBtn.disabled = false;
    return true;
}

/**
 * Update length display
 */
function updateLengthDisplay() {
    elements.lengthValue.textContent = state.length;

    // Update slider background gradient to show progress
    const percent = ((state.length - 8) / (128 - 8)) * 100;
    elements.lengthSlider.style.background =
        `linear-gradient(to right, #8b5cf6 ${percent}%, rgba(255,255,255,0.1) ${percent}%)`;
}

/**
 * Update password count display
 */
function updateCountDisplay() {
    elements.passwordCountValue.textContent = state.passwordCount;

    // Update button states
    elements.countDecrease.disabled = state.passwordCount <= 1;
    elements.countIncrease.disabled = state.passwordCount >= 10;
}

/**
 * Render the generated passwords
 * @param {string[]} passwords - Array of passwords to display
 */
function renderPasswords(passwords) {
    if (passwords.length === 0) return;

    // Update primary password display
    elements.primaryPassword.value = passwords[0];
    elements.primaryCopyBtn.disabled = false;
    updateStrengthIndicator(passwords[0]);

    // Handle multiple passwords
    if (passwords.length > 1) {
        elements.passwordsListSection.classList.add('visible');
        elements.passwordsList.innerHTML = '';

        passwords.forEach((password, index) => {
            const item = document.createElement('div');
            item.className = 'password-item';
            item.innerHTML = `
                <span class="password-item-number">#${index + 1}</span>
                <span class="password-item-text">${escapeHtml(password)}</span>
                <button class="password-item-copy" title="Copy password" data-password="${escapeHtml(password)}">
                    <svg class="copy-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M16 1H4C2.9 1 2 1.9 2 3V17H4V3H16V1ZM19 5H8C6.9 5 6 5.9 6 7V21C6 22.1 6.9 23 8 23H19C20.1 23 21 22.1 21 21V7C21 5.9 20.1 5 19 5ZM19 21H8V7H19V21Z" fill="currentColor"/>
                    </svg>
                    <svg class="check-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                        <path d="M9 16.17L4.83 12L3.41 13.41L9 19L21 7L19.59 5.59L9 16.17Z" fill="currentColor"/>
                    </svg>
                </button>
            `;
            elements.passwordsList.appendChild(item);
        });
    } else {
        elements.passwordsListSection.classList.remove('visible');
    }
}

/**
 * Escape HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// =============================================================================
// Event Handlers
// =============================================================================

function handleGenerate() {
    if (!validateOptions()) return;

    // Add visual feedback animation
    elements.generateBtn.querySelector('.generate-icon').style.transform = 'rotate(360deg)';
    setTimeout(() => {
        elements.generateBtn.querySelector('.generate-icon').style.transform = '';
    }, 300);

    const passwords = generateMultiplePasswords(state.passwordCount);
    renderPasswords(passwords);
}

function handleLengthChange(e) {
    state.length = parseInt(e.target.value, 10);
    updateLengthDisplay();
}

function handleOptionChange(option, value) {
    state.options[option] = value;
    validateOptions();
}

function handleCountChange(delta) {
    const newCount = state.passwordCount + delta;
    if (newCount >= 1 && newCount <= 10) {
        state.passwordCount = newCount;
        updateCountDisplay();
    }
}

function handlePasswordListCopy(e) {
    const copyBtn = e.target.closest('.password-item-copy');
    if (copyBtn) {
        const password = copyBtn.dataset.password;
        copyToClipboard(password, copyBtn, false); // Don't show popup for list items
    }
}

function toggleMobileMenu() {
    elements.mobileMenu.classList.toggle('active');
}

function closeMobileMenu() {
    elements.mobileMenu.classList.remove('active');
}

// =============================================================================
// FAQ Accordion
// =============================================================================

function initFaqAccordion() {
    const faqItems = document.querySelectorAll('.faq-item');

    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');

        question.addEventListener('click', () => {
            const isActive = item.classList.contains('active');

            // Close all items
            faqItems.forEach(otherItem => {
                otherItem.classList.remove('active');
                otherItem.querySelector('.faq-question').setAttribute('aria-expanded', 'false');
            });

            // Toggle current item
            if (!isActive) {
                item.classList.add('active');
                question.setAttribute('aria-expanded', 'true');
            }
        });
    });
}

// =============================================================================
// Smooth Scrolling for Navigation
// =============================================================================

function initSmoothScrolling() {
    const links = document.querySelectorAll('a[href^="#"]');

    links.forEach(link => {
        link.addEventListener('click', (e) => {
            const targetId = link.getAttribute('href');
            if (targetId === '#') return;

            const target = document.querySelector(targetId);
            if (target) {
                e.preventDefault();
                closeMobileMenu();

                const navHeight = 72;
                const targetPosition = target.getBoundingClientRect().top + window.pageYOffset - navHeight;

                window.scrollTo({
                    top: targetPosition,
                    behavior: 'smooth'
                });
            }
        });
    });
}

// =============================================================================
// Initialization
// =============================================================================

function init() {
    // Set initial UI state
    updateLengthDisplay();
    updateCountDisplay();
    validateOptions();

    // Event listeners - Length slider
    elements.lengthSlider.addEventListener('input', handleLengthChange);

    // Event listeners - Character type toggles
    elements.includeUppercase.addEventListener('change', (e) => {
        handleOptionChange('uppercase', e.target.checked);
    });
    elements.includeLowercase.addEventListener('change', (e) => {
        handleOptionChange('lowercase', e.target.checked);
    });
    elements.includeNumbers.addEventListener('change', (e) => {
        handleOptionChange('numbers', e.target.checked);
    });
    elements.includeSymbols.addEventListener('change', (e) => {
        handleOptionChange('symbols', e.target.checked);
    });

    // Event listeners - Additional options
    elements.excludeSimilar.addEventListener('change', (e) => {
        handleOptionChange('excludeSimilar', e.target.checked);
    });

    // Event listeners - Password count
    elements.countDecrease.addEventListener('click', () => handleCountChange(-1));
    elements.countIncrease.addEventListener('click', () => handleCountChange(1));

    // Event listeners - Generate button
    elements.generateBtn.addEventListener('click', handleGenerate);

    // Event listeners - Copy buttons
    elements.primaryCopyBtn.addEventListener('click', () => {
        copyToClipboard(elements.primaryPassword.value, elements.primaryCopyBtn);
    });

    elements.passwordsList.addEventListener('click', handlePasswordListCopy);

    // Event listeners - Mobile menu
    if (elements.mobileMenuBtn) {
        elements.mobileMenuBtn.addEventListener('click', toggleMobileMenu);
    }

    // Keyboard shortcut - Enter to generate
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !elements.generateBtn.disabled) {
            handleGenerate();
        }
        // Escape to close popup
        if (e.key === 'Escape' && elements.copyPopupOverlay.classList.contains('active')) {
            closeCopyPopup();
        }
    });

    // Copy popup event listeners
    if (elements.copyPopupClose) {
        elements.copyPopupClose.addEventListener('click', closeCopyPopup);
    }
    if (elements.copyPopupOverlay) {
        elements.copyPopupOverlay.addEventListener('click', (e) => {
            if (e.target === elements.copyPopupOverlay) {
                closeCopyPopup();
            }
        });
    }
    if (elements.copyAgainBtn) {
        elements.copyAgainBtn.addEventListener('click', copyFromPopup);
    }
    if (elements.generateNewBtn) {
        elements.generateNewBtn.addEventListener('click', generateFromPopup);
    }

    // Initialize FAQ accordion
    initFaqAccordion();

    // Initialize smooth scrolling
    initSmoothScrolling();

    // Initialize ads safely after page is ready
    initAds();

    // Generate initial password
    handleGenerate();
}

// =============================================================================
// AdSense Safe Initialization
// =============================================================================

/**
 * Safely initialize AdSense ads after page is ready
 * This prevents the "No slot size for availableWidth=0" error
 */
function initAds() {
    // Only initialize ads on http/https (not file://)
    if (window.location.protocol === 'file:') {
        console.log('AdSense: Skipping initialization on file:// protocol');
        return;
    }

    // Wait for the page to be fully interactive
    if (document.readyState === 'complete') {
        loadAllAds();
    } else {
        window.addEventListener('load', loadAllAds);
    }
}

/**
 * Load all AdSense ad units on the page
 */
function loadAllAds() {
    // Small delay to ensure all elements have rendered
    setTimeout(() => {
        const adUnits = document.querySelectorAll('.adsbygoogle');

        adUnits.forEach((adUnit, index) => {
            // Check if ad container is visible
            const rect = adUnit.getBoundingClientRect();
            if (rect.width > 0) {
                try {
                    (window.adsbygoogle = window.adsbygoogle || []).push({});
                } catch (e) {
                    console.log(`AdSense unit ${index}: ${e.message}`);
                }
            } else {
                // If not visible, try again when it becomes visible
                observeAdVisibility(adUnit);
            }
        });
    }, 500);
}

/**
 * Observe when an ad unit becomes visible and then initialize it
 */
function observeAdVisibility(adUnit) {
    if ('IntersectionObserver' in window) {
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting && entry.boundingClientRect.width > 0) {
                    try {
                        (window.adsbygoogle = window.adsbygoogle || []).push({});
                    } catch (e) {
                        console.log('AdSense lazy load:', e.message);
                    }
                    observer.disconnect();
                }
            });
        }, { threshold: 0.1 });

        observer.observe(adUnit);
    }
}

// Start the application
document.addEventListener('DOMContentLoaded', init);
