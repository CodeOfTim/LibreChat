import { useEffect, useState } from 'react';
import { ErrorTypes, registerPage } from 'librechat-data-provider';
import { OpenIDIcon, useToastContext } from '@librechat/client';
import { useOutletContext, useSearchParams, useLocation } from 'react-router-dom';
import type { TLoginLayoutContext } from '~/common';
import { getLoginError, persistRedirectToSession } from '~/utils';
import { ErrorMessage } from '~/components/Auth/ErrorMessage';
import SocialButton from '~/components/Auth/SocialButton';
import { useAuthContext } from '~/hooks/AuthContext';
import { useLocalize } from '~/hooks';
import LoginForm from './LoginForm';

interface LoginLocationState {
  redirect_to?: string;
}

function Login() {
  const localize = useLocalize();
  const { showToast } = useToastContext();
  const { error, setError, login } = useAuthContext();
  const { startupConfig } = useOutletContext<TLoginLayoutContext>();

  const [searchParams, setSearchParams] = useSearchParams();
  const location = useLocation();
  const disableAutoRedirect = searchParams.get('redirect') === 'false';

  const [isAutoRedirectDisabled, setIsAutoRedirectDisabled] = useState(disableAutoRedirect);

  useEffect(() => {
    const redirectTo = searchParams.get('redirect_to');
    if (redirectTo) {
      persistRedirectToSession(redirectTo);
    } else {
      const state = location.state as LoginLocationState | null;
      if (state?.redirect_to) {
        persistRedirectToSession(state.redirect_to);
      }
    }

    const oauthError = searchParams?.get('error');
    if (oauthError && oauthError === ErrorTypes.AUTH_FAILED) {
      showToast({
        message: localize('com_auth_error_oauth_failed'),
        status: 'error',
      });
      const newParams = new URLSearchParams(searchParams);
      newParams.delete('error');
      setSearchParams(newParams, { replace: true });
    }
  }, [searchParams, setSearchParams, showToast, localize, location.state]);

  useEffect(() => {
    if (disableAutoRedirect) {
      setIsAutoRedirectDisabled(true);
      const newParams = new URLSearchParams(searchParams);
      newParams.delete('redirect');
      setSearchParams(newParams, { replace: true });
    }
  }, [disableAutoRedirect, searchParams, setSearchParams]);

  const shouldAutoRedirect =
    startupConfig?.openidLoginEnabled &&
    startupConfig?.openidAutoRedirect &&
    startupConfig?.serverDomain &&
    !isAutoRedirectDisabled;

  useEffect(() => {
    if (shouldAutoRedirect) {
      console.log('Auto-redirecting to OpenID provider...');
      window.location.href = `${startupConfig.serverDomain}/oauth/openid`;
    }
  }, [shouldAutoRedirect, startupConfig]);

  // ── Forwarded auth debug panel state ──────────────────────────────────────
  // These hooks must live before any early return.
  type ForwardedAuthDebug = {
    status: string;
    config: Record<string, string | boolean | null>;
    resolution: { username: string | null; email: string | null; source: string } | null;
    headers: Record<string, { present: boolean; value?: string; length?: number; type?: string; decoded?: Record<string, unknown>; decodeError?: string | null }>;
    issues: string[];
    hint: string | null;
  };
  const [forwardedAuthDebug, setForwardedAuthDebug] = useState<ForwardedAuthDebug | null>(null);
  const [forwardedAuthDebugLoading, setForwardedAuthDebugLoading] = useState(false);

  useEffect(() => {
    if (!startupConfig?.forwardedAuthEnabled) {
      return;
    }
    setForwardedAuthDebugLoading(true);
    fetch('/api/auth/forwarded-auth/debug', { credentials: 'include' })
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        setForwardedAuthDebug(data as ForwardedAuthDebug | null);
        setForwardedAuthDebugLoading(false);
      })
      .catch(() => setForwardedAuthDebugLoading(false));
  }, [startupConfig?.forwardedAuthEnabled]);

  if (shouldAutoRedirect) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center p-4">
        <p className="text-lg font-semibold">
          {localize('com_ui_redirecting_to_provider', { 0: startupConfig.openidLabel })}
        </p>
        <div className="mt-4">
          <SocialButton
            key="openid"
            enabled={startupConfig.openidLoginEnabled}
            serverDomain={startupConfig.serverDomain}
            oauthPath="openid"
            Icon={() =>
              startupConfig.openidImageUrl ? (
                <img src={startupConfig.openidImageUrl} alt="OpenID Logo" className="h-5 w-5" />
              ) : (
                <OpenIDIcon />
              )
            }
            label={startupConfig.openidLabel}
            id="openid"
          />
        </div>
      </div>
    );
  }

  // Check if forwarded auth is enabled
  const isForwardedAuthEnabled = startupConfig?.forwardedAuthEnabled;

  // Render fallback UI if forwarded auth is enabled.
  // AuthContext's silentRefresh() will pick up the refresh cookie set by the server
  // middleware on the initial page load and authenticate the user automatically.
  if (isForwardedAuthEnabled) {
    const debugOk = forwardedAuthDebug?.status === 'would-authenticate';

    return (
      <div className="flex min-h-screen flex-col items-center justify-center p-4">
        <p className="text-lg font-semibold">{localize('com_auth_authenticating')}</p>

        {/* Debug panel — always visible when forwarded auth is active */}
        <div className="mt-8 w-full max-w-2xl rounded-lg border border-gray-200 bg-white p-4 text-left shadow-sm dark:border-gray-700 dark:bg-gray-900">
          <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
            Forwarded Auth Debug
          </p>

          {forwardedAuthDebugLoading && (
            <p className="text-xs text-gray-400">Loading debug info…</p>
          )}

          {forwardedAuthDebug && (
            <>
              <span
                className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
                  debugOk
                    ? 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300'
                    : 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300'
                }`}
              >
                {forwardedAuthDebug.status}
              </span>

              {forwardedAuthDebug.resolution && (
                <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="font-medium text-gray-600 dark:text-gray-400">Username: </span>
                    <code className="font-mono">
                      {forwardedAuthDebug.resolution.username ?? '(none)'}
                    </code>
                  </div>
                  <div>
                    <span className="font-medium text-gray-600 dark:text-gray-400">Email: </span>
                    <code className="font-mono">
                      {forwardedAuthDebug.resolution.email ?? '(none)'}
                    </code>
                  </div>
                  <div className="col-span-2">
                    <span className="font-medium text-gray-600 dark:text-gray-400">Source: </span>
                    <code className="font-mono">{forwardedAuthDebug.resolution.source}</code>
                  </div>
                </div>
              )}

              {forwardedAuthDebug.issues.length > 0 && (
                <div className="mt-3">
                  <p className="text-xs font-semibold text-red-600 dark:text-red-400">Issues:</p>
                  <ul className="mt-1 list-disc pl-4 text-xs text-red-700 dark:text-red-300">
                    {forwardedAuthDebug.issues.map((issue, i) => (
                      <li key={i}>{issue}</li>
                    ))}
                  </ul>
                </div>
              )}

              {forwardedAuthDebug.hint && (
                <p className="mt-2 text-xs text-amber-600 dark:text-amber-400">
                  {forwardedAuthDebug.hint}
                </p>
              )}

              <details className="mt-3">
                <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700 dark:hover:text-gray-300">
                  Received headers &amp; config
                </summary>
                <pre className="mt-2 max-h-64 overflow-auto rounded bg-gray-50 p-3 text-xs leading-relaxed dark:bg-gray-800">
                  {JSON.stringify(
                    { config: forwardedAuthDebug.config, headers: forwardedAuthDebug.headers },
                    null,
                    2,
                  )}
                </pre>
              </details>
            </>
          )}

          {!forwardedAuthDebugLoading && !forwardedAuthDebug && (
            <p className="text-xs text-gray-400">
              Debug endpoint unavailable — check server logs.
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <>
      {error != null && <ErrorMessage>{localize(getLoginError(error))}</ErrorMessage>}
      {startupConfig?.emailLoginEnabled === true && (
        <LoginForm
          onSubmit={login}
          startupConfig={startupConfig}
          error={error}
          setError={setError}
        />
      )}
      {startupConfig?.registrationEnabled === true && (
        <p className="my-4 text-center text-sm font-light text-gray-700 dark:text-white">
          {' '}
          {localize('com_auth_no_account')}{' '}
          <a
            href={registerPage()}
            className="inline-flex p-1 text-sm font-medium text-green-600 underline decoration-transparent transition-all duration-200 hover:text-green-700 hover:decoration-green-700 focus:text-green-700 focus:decoration-green-700 dark:text-green-500 dark:hover:text-green-400 dark:hover:decoration-green-400 dark:focus:text-green-400 dark:focus:decoration-green-400"
          >
            {localize('com_auth_sign_up')}
          </a>
        </p>
      )}
    </>
  );
}

export default Login;
