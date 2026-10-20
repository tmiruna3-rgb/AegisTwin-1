import { ArrowLeft, ArrowRight, CheckCircle2, Code2, LockKeyhole, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'

import { BrandMark } from '../components/layout/BrandMark'
import { DigitalTwinDemo } from '../components/marketing/DigitalTwinDemo'
import { isDevelopmentSession } from '../lib/auth'
import { appRoutes } from '../lib/routes'
import { getSession } from '../services/sessionApi'
import type { SessionView } from '../types/session'

function safeDestination(candidate: string | null): string {
  if (!candidate) return '/app'
  try {
    const base = new URL('https://aegisarena.local')
    const parsed = new URL(candidate, base)
    const permitted = appRoutes.some(
      ({ path }) => parsed.pathname === path || parsed.pathname.startsWith(`${path}/`),
    )
    if (parsed.origin !== base.origin || !permitted) return '/app'
    return `${parsed.pathname}${parsed.search}${parsed.hash}`
  } catch {
    return '/app'
  }
}

export function LoginPage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const destination = safeDestination(params.get('next'))
  const [checking, setChecking] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [developmentSession, setDevelopmentSession] = useState<SessionView | null>(null)

  useEffect(() => {
    let active = true
    void getSession()
      .then((session) => {
        if (!active) return
        if (session.authenticated && session.auth_mode === 'easy_auth') {
          void navigate(destination, { replace: true })
          return
        }
        if (isDevelopmentSession(session)) {
          setDevelopmentSession(session)
        } else if (session.authenticated && session.auth_mode === 'development_bypass') {
          setError('An unsafe production development session was rejected.')
        }
        setChecking(false)
      })
      .catch(() => {
        if (active) {
          setError(
            'The local backend or deployment identity service could not be reached. Start the AegisArena backend, then retry.',
          )
          setChecking(false)
        }
      })
    return () => {
      active = false
    }
  }, [destination, navigate])

  const signInUrl = `/.auth/login/google?post_login_redirect_uri=${encodeURIComponent(destination)}`

  return (
    <main className="login-shell">
      <section className="login-story">
        <Link className="marketing-brand" to="/">
          <BrandMark /> <strong>AegisArena</strong>
        </Link>
        <div className="login-story-copy">
          <p className="public-eyebrow">Autonomous cloud cyber range</p>
          <h1>
            Security decisions,
            <br />
            made visible.
          </h1>
          <p>
            Access the Command Centre, synchronized Digital Twin, and coordinated Red and Blue Agent
            workflows.
          </p>
          <div className="login-benefits">
            <span>
              <CheckCircle2 /> Role-based access
            </span>
            <span>
              <CheckCircle2 /> Backend-verified identity
            </span>
            <span>
              <CheckCircle2 /> Complete simulation audit trail
            </span>
          </div>
        </div>
        <div className="login-visual">
          <DigitalTwinDemo />
        </div>
      </section>
      <section className="login-panel-wrap">
        <Link className="login-back" to="/">
          <ArrowLeft /> Back to home
        </Link>
        <div className="login-card">
          <span className="login-lock">
            <LockKeyhole />
          </span>
          <h2>Welcome to AegisArena</h2>
          <p>Sign in to continue to your cloud security Command Centre.</p>
          {error ? (
            <div className="login-error" role="alert">
              {error}
            </div>
          ) : null}
          {developmentSession ? (
            <div className="development-entry" aria-label="Development Mode">
              <span className="development-entry-icon">
                <Code2 aria-hidden="true" />
              </span>
              <span>
                <strong>Development Mode</strong>
                <small>
                  Backend-verified {developmentSession.role.toLowerCase()} access for this local
                  environment.
                </small>
              </span>
              <button
                type="button"
                className="public-btn public-btn-primary"
                onClick={() => {
                  void navigate(destination)
                }}
              >
                Enter development console <ArrowRight aria-hidden="true" />
              </button>
              <p>
                Enabled by the backend’s <code>AUTH_DEV_BYPASS_ROLE</code>. Roles cannot be chosen
                here, and API authorization remains enforced.
              </p>
            </div>
          ) : null}
          <a className="entra-button" href={signInUrl} aria-disabled={checking}>
            <span className="microsoft-mark" aria-hidden="true">
              <i />
              <i />
              <i />
              <i />
            </span>
            {checking ? 'Checking your session…' : 'Sign in with Google'}
            <ArrowRight aria-hidden="true" />
          </a>
          <div className="login-divider">
            <span>
              {developmentSession ? 'Deployment sign-in' : 'Secure organizational access'}
            </span>
          </div>
          <div className="login-security-note">
            <ShieldCheck />
            <span>
              <strong>Authentication is handled by Google through Azure.</strong>Your password and
              access token are never collected by this interface.
            </span>
          </div>
        </div>
        <p className="login-footnote">
          Access is subject to your organization’s identity and role policies.
        </p>
      </section>
    </main>
  )
}
