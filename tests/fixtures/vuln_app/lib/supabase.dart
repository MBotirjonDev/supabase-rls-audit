// Intentionally vulnerable Flutter client used by the test suite.
import 'package:supabase_flutter/supabase_flutter.dart';

const supabaseUrl = 'https://xyzcompany.supabase.co';
const serviceRoleKey = String.fromEnvironment('SUPABASE_SERVICE_ROLE_KEY');

Future<void> init() => Supabase.initialize(url: supabaseUrl, anonKey: serviceRoleKey);
