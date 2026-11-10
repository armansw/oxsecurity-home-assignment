import { type ReactElement, type SubmitEvent, useId, useState } from 'react';

interface ScanFormProps {
  readonly disabled: boolean;
  /** Server-side error to show under the input (e.g. INVALID_REPO_URL). */
  readonly serverError: string | null;
  readonly onSubmit: (repoUrl: string) => void;
}

export function validateRepoUrl(raw: string): string | null {
  const value = raw.trim();
  if (value === '') return 'Enter a repository URL.';
  if (!value.startsWith('https://')) return 'The repository URL must start with https://';
  return null;
}

export function ScanForm({ disabled, serverError, onSubmit }: ScanFormProps): ReactElement {
  const [repoUrl, setRepoUrl] = useState('');
  const [clientError, setClientError] = useState<string | null>(null);
  const inputId = useId();
  const errorId = useId();
  const error = clientError ?? serverError;

  const handleSubmit = (event: SubmitEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const validation = validateRepoUrl(repoUrl);
    setClientError(validation);
    if (validation === null) onSubmit(repoUrl.trim());
  };

  return (
    <form className="scan-form" onSubmit={handleSubmit} noValidate>
      <label htmlFor={inputId}>Repository URL</label>
      <div className="scan-form__row">
        <input
          id={inputId}
          type="url"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          placeholder="https://github.com/<owner>/<repo>"
          value={repoUrl}
          onChange={(e) => {
            setRepoUrl(e.target.value);
            setClientError(null);
          }}
          aria-invalid={error !== null}
          aria-describedby={error === null ? undefined : errorId}
        />
        <button type="submit" disabled={disabled}>
          Start
        </button>
      </div>
      {error !== null && (
        <p id={errorId} className="field-error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
