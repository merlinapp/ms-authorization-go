// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import gin "github.com/gin-gonic/gin"
import http "net/http"
import mock "github.com/stretchr/testify/mock"

// Auth is an autogenerated mock type for the Auth type
type Auth struct {
	mock.Mock
}

// BackAuthMiddleware provides a mock function with given fields: h
func (_m *Auth) BackAuthMiddleware(h http.Handler) http.Handler {
	ret := _m.Called(h)

	var r0 http.Handler
	if rf, ok := ret.Get(0).(func(http.Handler) http.Handler); ok {
		r0 = rf(h)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Handler)
		}
	}

	return r0
}

// GinBackAuthMiddleware provides a mock function with given fields:
func (_m *Auth) GinBackAuthMiddleware() gin.HandlerFunc {
	ret := _m.Called()

	var r0 gin.HandlerFunc
	if rf, ok := ret.Get(0).(func() gin.HandlerFunc); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(gin.HandlerFunc)
		}
	}

	return r0
}

// GinTokenAndBackAuthMiddleware provides a mock function with given fields:
func (_m *Auth) GinTokenAndBackAuthMiddleware() gin.HandlerFunc {
	ret := _m.Called()

	var r0 gin.HandlerFunc
	if rf, ok := ret.Get(0).(func() gin.HandlerFunc); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(gin.HandlerFunc)
		}
	}

	return r0
}

// GinTokenAuthMiddleware provides a mock function with given fields:
func (_m *Auth) GinTokenAuthMiddleware() gin.HandlerFunc {
	ret := _m.Called()

	var r0 gin.HandlerFunc
	if rf, ok := ret.Get(0).(func() gin.HandlerFunc); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(gin.HandlerFunc)
		}
	}

	return r0
}

// TokenAndBackAuthMiddleware provides a mock function with given fields: h
func (_m *Auth) TokenAndBackAuthMiddleware(h http.Handler) http.Handler {
	ret := _m.Called(h)

	var r0 http.Handler
	if rf, ok := ret.Get(0).(func(http.Handler) http.Handler); ok {
		r0 = rf(h)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Handler)
		}
	}

	return r0
}

// TokenAuthMiddleware provides a mock function with given fields: h
func (_m *Auth) TokenAuthMiddleware(h http.Handler) http.Handler {
	ret := _m.Called(h)

	var r0 http.Handler
	if rf, ok := ret.Get(0).(func(http.Handler) http.Handler); ok {
		r0 = rf(h)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(http.Handler)
		}
	}

	return r0
}
