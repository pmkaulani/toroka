import React from "react";

interface RevealModalProps {
  pseudonym: string;
  plaintextIdentity: string;
  consumedAt: string;
  onClose: () => void;
}

export const RevealModal: React.FC<RevealModalProps> = ({
  pseudonym,
  plaintextIdentity,
  consumedAt,
  onClose,
}) => {
  return (
    <div className="modal-overlay">
      <div className="modal-box" style={{ maxWidth: 540 }}>
        <div className="modal-header" style={{ borderBottomColor: "var(--accent-amber)" }}>
          <h3 className="modal-title" style={{ color: "var(--accent-amber)" }}>
            ⚠️ Single-Use Plaintext Identity Reveal
          </h3>
          <button
            onClick={onClose}
            style={{
              background: "transparent",
              border: "none",
              color: "var(--text-muted)",
              cursor: "pointer",
              fontSize: 18,
            }}
          >
            ✕
          </button>
        </div>

        <div className="modal-body">
          <div
            className="notice-banner"
            style={{
              backgroundColor: "rgba(244, 63, 94, 0.1)",
              borderColor: "var(--accent-rose)",
              color: "#fda4af",
              marginBottom: 20,
            }}
          >
            <strong>BANK SECURITY MANDATE:</strong> This pseudonym has now been consumed from the separated
            identity vault. This plaintext will NOT be accessible again and is not stored in your browser cache or
            casework notes. You must record necessary actions within authorised bank logging channels only.
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase" }}>
              Vault Pseudonym
            </label>
            <div className="code-mono" style={{ padding: "8px 12px", marginTop: 4, display: "block" }}>
              {pseudonym}
            </div>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ fontSize: 11, color: "var(--accent-emerald)", fontWeight: 700, textTransform: "uppercase" }}>
              Decrypted Plaintext Identity
            </label>
            <div
              style={{
                fontFamily: "var(--font-mono)",
                fontSize: 16,
                fontWeight: 700,
                color: "#10b981",
                backgroundColor: "#052e16",
                padding: "12px 16px",
                borderRadius: 6,
                border: "1px solid #10b981",
                marginTop: 4,
                wordBreak: "break-all",
              }}
            >
              {plaintextIdentity}
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, color: "var(--text-dim)" }}>
              Consumption Timestamp: {new Date(consumedAt).toLocaleString()}
            </label>
          </div>
        </div>

        <div className="modal-footer">
          <button className="wb-btn wb-btn-primary" onClick={onClose}>
            Acknowledge &amp; Purge Plaintext from Memory
          </button>
        </div>
      </div>
    </div>
  );
};
