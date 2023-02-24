import { createCSRF, handler, mockAdapter } from "./utils"
import EmailProvider from "../src/providers/email"

it("Send e-mail to the only address correctly", async () => {
  const { secret, csrf } = await createCSRF()

  const sendVerificationRequest = jest.fn()
  const signIn = jest.fn(() => true)

  const email = "email@example.com"
  const { res } = await handler(
    {
      adapter: mockAdapter(),
      providers: [EmailProvider({ sendVerificationRequest })],
      callbacks: { signIn },
      secret,
      trustHost: true,
    },
    {
      path: "signin/email",
      requestInit: {
        method: "POST",
        headers: { cookie: csrf.cookie, "content-type": "application/json" },
        body: JSON.stringify({ email: email, csrfToken: csrf.value }),
      },
    }
  )

  expect(res.redirect).toBe(
    "http://localhost:3000/api/auth/verify-request?provider=email&type=email"
  )

  expect(signIn).toBeCalledTimes(1)
  expect(signIn).toHaveBeenCalledWith(
    expect.objectContaining({
      user: expect.objectContaining({ email }),
    })
  )

  expect(sendVerificationRequest).toHaveBeenCalledWith(
    expect.objectContaining({ identifier: email })
  )
})

it("Send e-mail to first address only", async () => {
  const { secret, csrf } = await createCSRF()
  const sendVerificationRequest = jest.fn()
  const signIn = jest.fn(() => true)

  const firstEmail = "email@email.com"
  const email = `${firstEmail},email@email2.com`
  const { res } = await handler(
    {
      adapter: mockAdapter(),
      providers: [EmailProvider({ sendVerificationRequest })],
      callbacks: { signIn },
      secret,
      trustHost: true,
    },
    {
      path: "signin/email",
      requestInit: {
        method: "POST",
        headers: { cookie: csrf.cookie, "content-type": "application/json" },
        body: JSON.stringify({ email: email, csrfToken: csrf.value }),
      },
    }
  )

  expect(res.redirect).toBe(
    "http://localhost:3000/api/auth/verify-request?provider=email&type=email"
  )

  expect(signIn).toBeCalledTimes(1)
  expect(signIn).toHaveBeenCalledWith(
    expect.objectContaining({
      user: expect.objectContaining({ email: firstEmail }),
    })
  )

  expect(sendVerificationRequest).toHaveBeenCalledWith(
    expect.objectContaining({ identifier: firstEmail })
  )
})

it("Send e-mail to address with first domain", async () => {
  const { secret, csrf } = await createCSRF()
  const sendVerificationRequest = jest.fn()
  const signIn = jest.fn(() => true)

  const firstEmail = "email@email.com"
  const email = `${firstEmail},email2.com`
  const { res } = await handler(
    {
      adapter: mockAdapter(),
      providers: [EmailProvider({ sendVerificationRequest })],
      callbacks: { signIn },
      secret,
      trustHost: true,
    },
    {
      path: "signin/email",
      requestInit: {
        method: "POST",
        headers: { cookie: csrf.cookie, "content-type": "application/json" },
        body: JSON.stringify({ email: email, csrfToken: csrf.value }),
      },
    }
  )

  expect(res.redirect).toBe(
    "http://localhost:3000/api/auth/verify-request?provider=email&type=email"
  )

  expect(signIn).toBeCalledTimes(1)
  expect(signIn).toHaveBeenCalledWith(
    expect.objectContaining({
      user: expect.objectContaining({ email: firstEmail }),
    })
  )

  expect(sendVerificationRequest).toHaveBeenCalledWith(
    expect.objectContaining({ identifier: firstEmail })
  )
})

it("Send e-mail to with query", async () => {
  const { secret, csrf } = await createCSRF()

  const sendVerificationRequest = jest.fn()
  const signIn = jest.fn(() => true)

  const email = "email@example.com"
  const { res } = await handler(
    {
      adapter: mockAdapter(),
      providers: [EmailProvider({ sendVerificationRequest })],
      callbacks: { signIn },
      secret,
      trustHost: true,
    },
    {
      path: "signin/email",
      params: {
        foo: "bar",
      },
      requestInit: {
        method: "POST",
        headers: { cookie: csrf.cookie, "content-type": "application/json" },
        body: JSON.stringify({ email: email, csrfToken: csrf.value }),
      },
    }
  )

  expect(res.redirect).toBe(
    "http://localhost:3000/api/auth/verify-request?provider=email&type=email"
  )

  expect(signIn).toBeCalledTimes(1)
  expect(signIn).toHaveBeenCalledWith(
    expect.objectContaining({
      user: expect.objectContaining({ email }),
    })
  )

  expect(sendVerificationRequest).toHaveBeenCalledWith(
    expect.objectContaining({
      identifier: email,
      url: expect.stringContaining("foo=bar"),
    })
  )
})

it("Redirect to error page if multiple addresses aren't allowed", async () => {
  const { secret, csrf } = await createCSRF()
  const sendVerificationRequest = jest.fn()
  const signIn = jest.fn()
  const error = new Error("Only one email allowed")
  const { res, log } = await handler(
    {
      adapter: mockAdapter(),
      callbacks: { signIn },
      providers: [
        EmailProvider({
          sendVerificationRequest,
          normalizeIdentifier(identifier) {
            if (identifier.split("@").length > 2) throw error
            return identifier
          },
        }),
      ],
      secret,
      trustHost: true,
    },
    {
      path: "signin/email",
      requestInit: {
        method: "POST",
        headers: { cookie: csrf.cookie, "content-type": "application/json" },
        body: JSON.stringify({
          email: "email@email.com,email@email2.com",
          csrfToken: csrf.value,
        }),
      },
    }
  )

  expect(signIn).toBeCalledTimes(0)
  expect(sendVerificationRequest).toBeCalledTimes(0)

  expect(log.error.mock.calls[0]).toEqual([
    "SIGNIN_EMAIL_ERROR",
    { error, providerId: "email" },
  ])

  expect(res.redirect).toBe(
    "http://localhost:3000/api/auth/error?error=EmailSignin"
  )
})

it("Handle e-mail callback", async () => {
  const email = "email@example.com"
  const token = "dummyToken"
  const signIn = jest.fn(() => true)
  const createUser = jest.fn(() => ({
    id: "dummyId",
    email,
    emailVerified: null,
  }))
  const { res } = await handler(
    {
      adapter: {
        ...mockAdapter(),
        createUser,
        createSession: () => ({} as any),
        useVerificationToken: () => ({
          identifier: email,
          expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
          token,
        }),
      },
      providers: [EmailProvider({})],
      callbacks: { signIn },
      trustHost: true,
    },
    {
      path: "callback/email",
      params: {
        email,
        token,
      },
      requestInit: {
        method: "GET",
      },
    }
  )

  expect(res.redirect).toBe("http://localhost:3000")
  expect(createUser).toHaveBeenCalledWith(expect.objectContaining({ email }))
})

it("Handle e-mail callback with query", async () => {
  const email = "email@example.com"
  const token = "dummyToken"
  const signIn = jest.fn(() => true)
  const createUser = jest.fn(() => ({
    id: "dummyId",
    email,
    emailVerified: null,
  }))
  const { res } = await handler(
    {
      adapter: {
        ...mockAdapter(),
        createUser,
        createSession: () => ({} as any),
        useVerificationToken: () => ({
          identifier: email,
          expires: new Date(Date.now() + 1000 * 60 * 60 * 24),
          token,
        }),
      },
      providers: [EmailProvider({})],
      callbacks: { signIn },
      trustHost: true,
    },
    {
      path: "callback/email",
      params: {
        email,
        token,
        foo: "bar",
      },
      requestInit: {
        method: "GET",
      },
    }
  )

  expect(res.redirect).toBe("http://localhost:3000")
  expect(createUser).toHaveBeenCalledWith(
    expect.objectContaining({ email, foo: "bar" })
  )
})
