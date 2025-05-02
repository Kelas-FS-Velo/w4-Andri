// services/validation.js
// Fungsi validasi sederhana untuk berbagai kebutuhan

/**
 * Validasi email
 * @param {string} email
 * @returns {boolean}
 */
export function validateEmail(email) {
  return /^[\w-.]+@([\w-]+\.)+[\w-]{2,}$/.test(email)
}

/**
 * Validasi password minimal 6 karakter
 * @param {string} password
 * @returns {boolean}
 */
export function validatePassword(password) {
  return typeof password === 'string' && password.length >= 6
}

/**
 * Validasi field tidak boleh kosong
 * @param {string} value
 * @returns {boolean}
 */
export function required(value) {
  return value !== undefined && value !== null && String(value).trim() !== ''
}

// Tambahkan fungsi validasi lain sesuai kebutuhan
