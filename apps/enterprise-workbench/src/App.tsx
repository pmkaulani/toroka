import React, { useState } from "react";
import "./App.css";
import { getCurrentPersona } from "./api";
import { AuditTrailView } from "./components/AuditTrailView";
import { CaseDetailModal } from "./components/CaseDetailModal";
import { CaseRegisterView } from "./components/CaseRegisterView";
import { DataReadinessView } from "./components/DataReadinessView";
import { Header } from "./components/Header";
import { IntegrationsView } from "./components/IntegrationsView";
import { InvestigationView } from "./components/InvestigationView";
import { MyCasesView } from "./components/MyCasesView";
import { OverviewView } from "./components/OverviewView";
import { ReviewQueuesView } from "./components/ReviewQueuesView";
import { RevealModal } from "./components/RevealModal";
import { Persona } from "./types";

export const App: React.FC = () => {
  const [persona, setPersona] = useState<Persona>(getCurrentPersona());
  const [activeTab, setActiveTab] = useState<string>("overview");
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  // Ephemeral single-use revealed identity state (purged immediately on dismiss)
  const [revealedData, setRevealedData] = useState<{
    pseudonym: string;
    plaintext: string;
    consumedAt: string;
  } | null>(null);

  const handlePersonaChange = (newPersona: Persona) => {
    setPersona(newPersona);
    // If Data Steward, force navigate to overview or data-readiness
    if (newPersona.role === "data_steward" && (activeTab === "my-cases" || activeTab === "cases" || activeTab === "review-queues")) {
      setActiveTab("data-readiness");
    }
  };

  const isDataSteward = persona.role === "data_steward";
  const isAuthoriser = persona.role === "authoriser";
  const isAuditor = persona.role === "auditor";
  const isAdmin = persona.role === "system_administrator";

  return (
    <div className="workbench-layout">
      <Header onPersonaChange={handlePersonaChange} installationId="toroka-default-installation" />

      {/* Navigation Bar */}
      <nav className="wb-nav">
        <button
          className={`wb-tab ${activeTab === "overview" ? "active" : ""}`}
          onClick={() => setActiveTab("overview")}
        >
          Operational Overview
        </button>

        {!isDataSteward && (
          <button
            className={`wb-tab ${activeTab === "my-cases" ? "active" : ""}`}
            onClick={() => setActiveTab("my-cases")}
          >
            My Cases
          </button>
        )}

        {(isAuthoriser || isAuditor || isAdmin) && (
          <button
            className={`wb-tab ${activeTab === "cases" ? "active" : ""}`}
            onClick={() => setActiveTab("cases")}
          >
            Case Register
          </button>
        )}

        {(isAuthoriser || isAdmin) && (
          <button
            className={`wb-tab ${activeTab === "review-queues" ? "active" : ""}`}
            onClick={() => setActiveTab("review-queues")}
          >
            Governance Queues
          </button>
        )}

        <button
          className={`wb-tab ${activeTab === "intelligence" ? "active" : ""}`}
          onClick={() => setActiveTab("intelligence")}
        >
          Fraud Intelligence
        </button>

        <button
          className={`wb-tab ${activeTab === "data-readiness" ? "active" : ""}`}
          onClick={() => setActiveTab("data-readiness")}
        >
          Data Contract v2.0.0
        </button>

        <button
          className={`wb-tab ${activeTab === "integrations" ? "active" : ""}`}
          onClick={() => setActiveTab("integrations")}
        >
          Source Integrations
        </button>

        {(isAuditor || isAuthoriser || isAdmin) && (
          <button
            className={`wb-tab ${activeTab === "audit-trail" ? "active" : ""}`}
            onClick={() => setActiveTab("audit-trail")}
          >
            Audit Hash Chain
          </button>
        )}
      </nav>

      {/* Main Workspace Body */}
      <main className="wb-content">
        {activeTab === "overview" && <OverviewView onNavigateTab={setActiveTab} />}
        {activeTab === "my-cases" && <MyCasesView onSelectCase={(id) => setSelectedCaseId(id)} />}
        {activeTab === "cases" && <CaseRegisterView onSelectCase={(id) => setSelectedCaseId(id)} />}
        {activeTab === "review-queues" && <ReviewQueuesView />}
        {activeTab === "intelligence" && (
          <InvestigationView
            initialCaseId={selectedCaseId}
            onSelectCase={(id) => setSelectedCaseId(id)}
          />
        )}
        {activeTab === "data-readiness" && <DataReadinessView />}
        {activeTab === "integrations" && <IntegrationsView />}
        {activeTab === "audit-trail" && <AuditTrailView />}
      </main>

      {/* Case Inspection Modal */}
      {selectedCaseId && activeTab !== "intelligence" && (
        <CaseDetailModal
          caseId={selectedCaseId}
          onClose={() => setSelectedCaseId(null)}
          onConsumeReveal={(pseudonym, plaintext, consumedAt) => {
            setRevealedData({ pseudonym, plaintext, consumedAt });
          }}
          onOpenIntelligence={(id) => {
            setSelectedCaseId(id);
            setActiveTab("intelligence");
          }}
        />
      )}

      {/* Ephemeral Plaintext Reveal Modal */}
      {revealedData && (
        <RevealModal
          pseudonym={revealedData.pseudonym}
          plaintextIdentity={revealedData.plaintext}
          consumedAt={revealedData.consumedAt}
          onClose={() => setRevealedData(null)}
        />
      )}
    </div>
  );
};
export default App;
