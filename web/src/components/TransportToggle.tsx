import type { ReactElement } from 'react';
import type { Transport } from '../api/types';

const OPTIONS: readonly { readonly value: Transport; readonly label: string }[] = [
  { value: 'rest', label: 'REST' },
  { value: 'graphql', label: 'GraphQL' },
];

interface TransportToggleProps {
  readonly value: Transport;
  readonly onChange: (transport: Transport) => void;
}

export function TransportToggle({ value, onChange }: TransportToggleProps): ReactElement {
  return (
    <fieldset className="toggle">
      <legend>Transport</legend>
      {OPTIONS.map((option) => (
        <label key={option.value} className="toggle__option">
          <input
            type="radio"
            name="transport"
            value={option.value}
            checked={value === option.value}
            onChange={() => {
              onChange(option.value);
            }}
          />
          <span>{option.label}</span>
        </label>
      ))}
    </fieldset>
  );
}
