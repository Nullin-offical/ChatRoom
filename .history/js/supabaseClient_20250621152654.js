// Supabase Client Configuration
// Initialize Supabase client with provided credentials

const SUPABASE_URL = 'https://dhngwqcvuwslbpkdxaja.supabase.co';
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRobmd3cWN2dXdzbGJwa2R4YWphIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTA1MDU2MTAsImV4cCI6MjA2NjA4MTYxMH0.FJAtWbm7G55CiRymLVK4tIXgaB2J-3-3mHwce2z85-k';

// Initialize Supabase client
const supabase = window.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Export for use in other modules
window.supabaseClient = supabase;

console.log('Supabase client initialized successfully'); 