// Shared auth + entitlement library for all CRE U / Deal Analyzer products
// Loads Supabase, manages session, exposes window.CREAuth API
//
// SUPABASE_URL and SUPABASE_ANON_KEY are PUBLIC values — safe to expose in
// the browser. The anon key is protected by Row Level Security policies in
// the database. Never put the SERVICE ROLE key in this file.

(function() {
  const SUPABASE_URL = "https://cglfliqwmpvldtjdknni.supabase.co";
  const SUPABASE_ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImNnbGZsaXF3bXB2bGR0amRrbm5pIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODEyNjgzNjEsImV4cCI6MjA5Njg0NDM2MX0.67Y4mTp_9-wD5hYXgDz3w2K9EiTESl9i5VbdSz1qekI";

  // Load Supabase JS client from CDN
  const supabaseScript = document.createElement("script");
  supabaseScript.src = "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2";
  document.head.appendChild(supabaseScript);

  supabaseScript.onload = () => {
    const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    window.CREAuth = {
      supabase,

      async getSession() {
        const { data } = await supabase.auth.getSession();
        return data.session;
      },

      async getUser() {
        const { data } = await supabase.auth.getUser();
        return data.user;
      },

      async signUp(email, password) {
        const { data, error } = await supabase.auth.signUp({ email, password });
        return { data, error };
      },

      async signIn(email, password) {
        const { data, error } = await supabase.auth.signInWithPassword({ email, password });
        return { data, error };
      },

      async signOut() {
        await supabase.auth.signOut();
        window.location.reload();
      },

      async resetPassword(email) {
        const { data, error } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: window.location.origin + "/reset-password.html"
        });
        return { data, error };
      },

      async hasEntitlement(productCode) {
        const session = await this.getSession();
        if (!session) return false;
        const { data, error } = await supabase
          .from("my_active_entitlements")
          .select("*")
          .eq("product_code", productCode)
          .maybeSingle();
        // --- TEMP DEBUG (remove once entitlement bug is fixed) ---
        console.log("ENTITLEMENT QUERY productCode:", productCode, "user:", session.user.id);
        console.log("ENTITLEMENT QUERY DATA:", data);
        console.log("ENTITLEMENT QUERY ERROR:", error);
        // --- END TEMP DEBUG ---
        return !error && !!data;
      },

      async loadProgress(productCode) {
        const session = await this.getSession();
        if (!session) return null;
        const { data } = await supabase
          .from("progress")
          .select("data")
          .eq("product_code", productCode)
          .maybeSingle();
        return data ? data.data : null;
      },

      async saveProgress(productCode, progressData) {
        const session = await this.getSession();
        if (!session) return false;
        const { error } = await supabase
          .from("progress")
          .upsert({
            user_id: session.user.id,
            product_code: productCode,
            data: progressData,
            updated_at: new Date().toISOString()
          });
        return !error;
      },

      onAuthStateChange(callback) {
        return supabase.auth.onAuthStateChange(callback);
      }
    };

    // Fire ready event
    document.dispatchEvent(new Event("creauth:ready"));
  };
})();
