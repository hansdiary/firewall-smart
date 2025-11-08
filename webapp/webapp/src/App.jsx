import { useEffect, useState } from "react";
import axios from "axios";

const API = "http://127.0.0.1:8000";

// --------------------
// Alert component
// --------------------
const Alert = ({ type, message }) => {
  const statusClasses = {
    info: "bg-blue-100 text-blue-800",
    success: "bg-green-100 text-green-800",
    error: "bg-red-100 text-red-800",
  };
  return (
    <div className={`mb-6 px-4 py-3 rounded shadow ${statusClasses[type]}`}>
      {message}
    </div>
  );
};

// --------------------
// Add Rule Form
// --------------------
const AddRuleForm = ({ onAdd }) => {
  const [ip, setIp] = useState("");
  const [port, setPort] = useState("");
  const [action, setAction] = useState("BLOCK");
  const [protocol, setProtocol] = useState("tcp");

  const handleAdd = () => {
    onAdd({
      ip: ip || null,
      port: port ? parseInt(port) : null,
      action,
      protocol,
    });
    setIp("");
    setPort("");
  };

  return (
    <div className="bg-white shadow-lg rounded-xl p-6 mb-10 max-w-full">
      <h2 className="text-2xl font-semibold mb-5 text-gray-700">➕ Ajouter une règle</h2>
      <div className="flex flex-wrap gap-4 items-center">
        <input
          className="border border-gray-300 rounded-lg px-4 py-2 min-w-[150px] max-w-[250px] focus:ring-2 focus:ring-blue-400 focus:outline-none"
          placeholder="IP"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <input
          className="border border-gray-300 rounded-lg px-4 py-2 w-32 min-w-[80px] focus:ring-2 focus:ring-blue-400 focus:outline-none"
          placeholder="Port (optionnel)"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <select
          className="border border-gray-300 rounded-lg px-4 py-2 w-36 min-w-[100px] focus:ring-2 focus:ring-blue-400 focus:outline-none"
          value={action}
          onChange={(e) => setAction(e.target.value)}
        >
          <option value="BLOCK">Bloquer</option>
          <option value="ALLOW">Autoriser</option>
        </select>
        <select
          className="border border-gray-300 rounded-lg px-4 py-2 w-36 min-w-[100px] focus:ring-2 focus:ring-blue-400 focus:outline-none"
          value={protocol}
          onChange={(e) => setProtocol(e.target.value)}
        >
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
        </select>
        <button
          className="bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition shadow"
          onClick={handleAdd}
        >
          Ajouter
        </button>
      </div>
    </div>
  );
};

// --------------------
// Rules Table
// --------------------
const RulesTable = ({ rules, onDelete }) => (
  <div className="bg-white shadow-lg rounded-xl p-6 max-w-full overflow-x-auto">
    <h2 className="text-2xl font-semibold mb-5 text-gray-700">📋 Liste des règles</h2>
    <table className="w-full table-fixed min-w-[600px] text-gray-700 border-collapse">
      <thead>
        <tr className="bg-gray-100 text-left">
          <th className="px-6 py-3 font-medium border-b">ID</th>
          <th className="px-6 py-3 font-medium border-b">IP</th>
          <th className="px-6 py-3 font-medium border-b">Port</th>
          <th className="px-6 py-3 font-medium border-b">Action</th>
          <th className="px-6 py-3 font-medium border-b">Protocole</th>
          <th className="px-6 py-3 font-medium border-b">Supprimer</th>
        </tr>
      </thead>
      <tbody>
        {rules.length === 0 ? (
          <tr>
            <td colSpan="6" className="text-center py-6 text-gray-400">
              Aucune règle trouvée
            </td>
          </tr>
        ) : (
          rules.map((r) => (
            <tr
              key={r.id}
              className="hover:bg-gray-50 transition-colors text-center"
            >
              <td className="px-6 py-3 border-b">{r.id}</td>
              <td className="px-6 py-3 border-b">{r.ip || "-"}</td>
              <td className="px-6 py-3 border-b">{r.port || "-"}</td>
              <td className="px-6 py-3 border-b">{r.action}</td>
              <td className="px-6 py-3 border-b">{r.protocol}</td>
              <td className="px-6 py-3 border-b">
                <button
                  className="bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition shadow"
                  onClick={() => onDelete(r.id, r.ip)}
                >
                  🗑️ Supprimer
                </button>
              </td>
            </tr>
          ))
        )}
      </tbody>
    </table>
  </div>
);

// --------------------
// Main App
// --------------------
export default function App() {
  const [rules, setRules] = useState([]);
  const [status, setStatus] = useState("");
  const [statusType, setStatusType] = useState("info");

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await axios.get(`${API}/rules`);
      setRules(res.data);
    } catch (err) {
      console.error(err);
      setStatus("❌ Impossible de charger les règles.");
      setStatusType("error");
    }
  };

  const addRule = async (rule) => {
    try {
      await axios.post(`${API}/rules`, rule);
      setStatus("✅ Règle ajoutée avec succès !");
      setStatusType("success");
      fetchRules();
    } catch (err) {
      console.error(err);
      setStatus("❌ Erreur lors de l'ajout de la règle.");
      setStatusType("error");
    }
  };

  const deleteRule = async (id, ip) => {
    if (!confirm(`Supprimer la règle pour ${ip || "toutes les IP"} ?`)) return;
    try {
      await axios.delete(`${API}/rules/${id}?ip=${ip}`);
      setStatus("🗑️ Règle supprimée !");
      setStatusType("success");
      fetchRules();
    } catch (err) {
      console.error(err);
      setStatus("❌ Suppression impossible.");
      setStatusType("error");
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 py-10 px-4 font-sans overflow-x-hidden">
      <div className="mx-auto max-w-[1280px]">
        <h1 className="text-4xl font-bold mb-8 text-center text-gray-800">
          🧠 Firewall Intelligent Dashboard
        </h1>

        {status && <Alert type={statusType} message={status} />}

        <AddRuleForm onAdd={addRule} />
        <RulesTable rules={rules} onDelete={deleteRule} />
      </div>
    </div>
  );
}
