import { Routes, Route, Navigate } from "react-router-dom";
import { RequireAuth, RequireOnboarded, RequirePermission } from "./auth/guards";
import { AppLayout } from "./components/AppLayout";
import { LoginPage } from "./pages/LoginPage";
import { OnboardingPage } from "./pages/OnboardingPage";
import { ConsentPage } from "./pages/ConsentPage";
import { ProfilePage } from "./pages/account/ProfilePage";
import { SecurityPage } from "./pages/account/SecurityPage";
import { MySessionsPage } from "./pages/account/MySessionsPage";
import { DashboardPage } from "./pages/admin/DashboardPage";
import { UsersPage } from "./pages/admin/UsersPage";
import { UserDetailPage } from "./pages/admin/UserDetailPage";
import { GroupsPage } from "./pages/admin/GroupsPage";
import { ApplicationsPage } from "./pages/admin/ApplicationsPage";
import { ApplicationDetailPage } from "./pages/admin/ApplicationDetailPage";
import { ClientsPage } from "./pages/admin/ClientsPage";
import { AuditPage } from "./pages/admin/AuditPage";
import { SettingsPage } from "./pages/admin/SettingsPage";
import { ApiTokensPage } from "./pages/admin/ApiTokensPage";
import { SecurityKeysPage } from "./pages/admin/SecurityKeysPage";
import { ApiDocsPage } from "./pages/ApiDocsPage";

function adminRoute(perm: string, el: React.ReactNode) {
  return <RequirePermission perm={perm}>{el}</RequirePermission>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/onboarding"
        element={
          <RequireAuth>
            <OnboardingPage />
          </RequireAuth>
        }
      />
      <Route
        path="/consent"
        element={
          <RequireAuth>
            <RequireOnboarded>
              <ConsentPage />
            </RequireOnboarded>
          </RequireAuth>
        }
      />

      <Route
        element={
          <RequireAuth>
            <RequireOnboarded>
              <AppLayout />
            </RequireOnboarded>
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/account" replace />} />
        <Route path="/account" element={<ProfilePage />} />
        <Route path="/account/security" element={<SecurityPage />} />
        <Route path="/account/sessions" element={<MySessionsPage />} />
        <Route path="/api-docs" element={<ApiDocsPage />} />

        <Route path="/admin/dashboard" element={adminRoute("iam.users.read", <DashboardPage />)} />
        <Route path="/admin/users" element={adminRoute("iam.users.read", <UsersPage />)} />
        <Route path="/admin/users/:id" element={adminRoute("iam.users.read", <UserDetailPage />)} />
        <Route path="/admin/groups" element={adminRoute("iam.groups.read", <GroupsPage />)} />
        <Route path="/admin/applications" element={adminRoute("iam.applications.read", <ApplicationsPage />)} />
        <Route path="/admin/applications/:id" element={adminRoute("iam.applications.read", <ApplicationDetailPage />)} />
        <Route path="/admin/clients" element={adminRoute("iam.clients.read", <ClientsPage />)} />
        <Route path="/admin/audit" element={adminRoute("iam.audit.read", <AuditPage />)} />
        <Route path="/admin/settings" element={adminRoute("iam.settings.read", <SettingsPage />)} />
        <Route path="/admin/api-tokens" element={adminRoute("iam.apptokens.read", <ApiTokensPage />)} />
        <Route path="/admin/security" element={adminRoute("iam.security.read", <SecurityKeysPage />)} />
      </Route>

      <Route path="*" element={<Navigate to="/account" replace />} />
    </Routes>
  );
}
