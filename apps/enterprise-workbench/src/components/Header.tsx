import React from "react";
import { BANK_PERSONAS, getCurrentPersona, setCurrentPersona } from "../api";
import { Persona } from "../types";

interface HeaderProps {
  onPersonaChange: (persona: Persona) => void;
  installationId: string;
}

export const Header: React.FC<HeaderProps> = ({ onPersonaChange, installationId }) => {
  const current = getCurrentPersona();

  const handleSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selected = BANK_PERSONAS.find((p) => p.id === e.target.value);
    if (selected) {
      setCurrentPersona(selected);
      onPersonaChange(selected);
    }
  };

  return (
    <header className="wb-header">
      <div className="wb-brand">
        <div className="wb-logo-mark">TOROKA</div>
        <div className="wb-title-box">
          <h1>Enterprise Investigation Workbench</h1>
          <p>Financial Crime &amp; Insider Risk Intelligence</p>
        </div>
      </div>

      <div className="wb-header-meta">
        <span className="wb-env-pill">PILOT ENVIRONMENT</span>
        <span className="code-mono" title="Installation ID">
          {installationId || "toroka-default-installation"}
        </span>

        <div className="wb-persona-select">
          <label htmlFor="persona-select">Operator Persona:</label>
          <select id="persona-select" value={current.id} onChange={handleSelect}>
            {BANK_PERSONAS.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} — {p.title} ({p.badge})
              </option>
            ))}
          </select>
        </div>
      </div>
    </header>
  );
};
