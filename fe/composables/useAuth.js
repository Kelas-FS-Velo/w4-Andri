import { ref } from 'vue'
import axios from 'axios'
import { jwtDecode } from 'jwt-decode'

const user = ref(null)
const token = ref(null)
const error = ref('')

export function useAuth() {
  // Load token from localStorage if exists
  if (process.client && !token.value) {
    token.value = localStorage.getItem('token')
    if (token.value) {
      try {
        user.value = jwtDecode(token.value)
      } catch (e) {
        user.value = null
      }
    }
  }

  const login = async (email, password) => {
    error.value = ''
    try {
      const { data } = await axios.post('http://localhost:8000/api/login', { email, password })
      token.value = data.token
      user.value = jwtDecode(data.token)
      localStorage.setItem('token', data.token)
      return true
    } catch (e) {
      error.value = e.response?.data?.error || 'Login gagal'
      return false
    }
  }

  const logout = () => {
    token.value = null
    user.value = null
    localStorage.removeItem('token')
  }

  const getUserInfo = async () => {
    if (!token.value) return null
    try {
      const { data } = await axios.get('http://localhost:8000/api/user', {
        headers: { Authorization: `Bearer ${token.value}` }
      })
      user.value = data
      return data
    } catch (e) {
      error.value = 'Token tidak valid atau expired'
      logout()
      return null
    }
  }

  return { user, token, error, login, logout, getUserInfo }
}
