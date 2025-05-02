import { ref } from 'vue'
import axios from 'axios'
import { jwtDecode } from 'jwt-decode'

const user = ref(null)
const token = ref(null)
const error = ref('')

function loadUser() {
  if (typeof window !== 'undefined') {
    const storedToken = localStorage.getItem('token')
    if (storedToken) {
      token.value = storedToken
      try {
        user.value = jwtDecode(storedToken)
      } catch (e) {
        user.value = null
      }
    }
  }
}

async function login(email, password) {
  error.value = ''
  try {
    const { data } = await axios.post('http://127.0.0.1:8000/api/login', { email, password })
    token.value = data.token
    try {
      user.value = jwtDecode(data.token)
    } catch (decodeErr) {
      user.value = null
      error.value = 'Token JWT tidak valid: ' + decodeErr.message
      return false
    }
    localStorage.setItem('token', data.token)
    return true
  } catch (e) {
    if (e.response && e.response.data && e.response.data.error) {
      error.value = e.response.data.error
    } else if (e.message) {
      error.value = 'Gagal login: ' + e.message
    } else {
      error.value = 'Login gagal (tidak diketahui)'
    }
    return false
  }
}

function logout() {
  token.value = null
  user.value = null
  localStorage.removeItem('token')
}

// Inisialisasi saat composable dipakai
loadUser()

export function useAuth() {
  return { user, token, error, login, logout, loadUser }
}
