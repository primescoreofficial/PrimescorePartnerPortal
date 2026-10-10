import { NextResponse } from 'next/server';
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;

const supabaseAdmin = createClient(supabaseUrl, serviceRoleKey, {
  auth: { autoRefreshToken: false, persistSession: false },
});

export async function POST(req: Request) {
  try {
    const adminHeader = req.headers.get('x-admin-password');
    const masterPassword = process.env.ADMIN_PASSWORD || 'Primescore@Admin2026';

    if (adminHeader !== masterPassword) {
      return NextResponse.json({ error: 'Unauthorized admin request.' }, { status: 401 });
    }

    const { partnerId, email, newPassword } = await req.json();
    const rawIdentifier = (email || partnerId || '').trim();

    if (!rawIdentifier || !newPassword) {
      return NextResponse.json({ error: 'Partner email or ID and newPassword are required.' }, { status: 400 });
    }

    if (newPassword.length < 6) {
      return NextResponse.json({ error: 'Password must be at least 6 characters long.' }, { status: 400 });
    }

    // 1. Resolve Target User Email from profiles table or direct email input
    let targetEmail = rawIdentifier.includes('@') ? rawIdentifier.toLowerCase() : '';
    let targetAuthId = rawIdentifier.includes('@') ? '' : rawIdentifier;

    if (!targetEmail) {
      const { data: prof } = await supabaseAdmin
        .from('profiles')
        .select('id, email')
        .eq('id', rawIdentifier)
        .maybeSingle();

      if (prof?.email) {
        targetEmail = prof.email.trim().toLowerCase();
        if (prof.id) targetAuthId = prof.id;
      }
    }

    if (!targetEmail && !targetAuthId) {
      return NextResponse.json({ error: `Could not find account for "${rawIdentifier}".` }, { status: 404 });
    }

    let userUpdated = false;

    // 2. Fetch users list with pagination support (perPage: 1000)
    const { data: userList } = await supabaseAdmin.auth.admin.listUsers({ page: 1, perPage: 1000 });
    const matchedUser = userList?.users?.find(
      (u) => (targetAuthId && u.id === targetAuthId) || (targetEmail && u.email?.toLowerCase() === targetEmail)
    );

    if (matchedUser) {
      const { error: updateErr } = await supabaseAdmin.auth.admin.updateUserById(matchedUser.id, {
        password: newPassword,
        email_confirm: true,
      });

      if (updateErr) {
        console.error('Supabase Auth updateUserById error:', updateErr.message);
        return NextResponse.json({ error: `Auth update failed: ${updateErr.message}` }, { status: 400 });
      }
      userUpdated = true;
    } else if (targetEmail) {
      // Partner exists in profiles but NOT in Supabase Auth.
      // Use generateLink (works even if Auth is invite-only, and auto-confirms email)
      const { data: linkData, error: linkErr } = await supabaseAdmin.auth.admin.generateLink({
        type: 'signup',
        email: targetEmail,
        password: newPassword,
        options: { data: { email_confirm: true } },
      });

      if (linkErr) {
        console.error('Supabase generateLink error:', linkErr.message);

        // Final fallback: try inviteUserByEmail if generateLink also fails
        const { data: invData, error: invErr } = await supabaseAdmin.auth.admin.inviteUserByEmail(targetEmail);
        if (invErr || !invData?.user?.id) {
          return NextResponse.json(
            { error: `Could not create auth account: ${linkErr.message}. Ensure SUPABASE_SERVICE_ROLE_KEY is set correctly and the Supabase project allows user creation.` },
            { status: 400 }
          );
        }
        // Invited — now set the password
        await supabaseAdmin.auth.admin.updateUserById(invData.user.id, { password: newPassword });
        // Link auth ID to profile
        if (targetAuthId && targetAuthId !== invData.user.id) {
          await supabaseAdmin.from('profiles').update({ id: invData.user.id }).eq('id', targetAuthId);
        }
        userUpdated = true;
      } else {
        const newAuthId = linkData?.user?.id;
        userUpdated = true;

        // Link newly generated Auth ID back to the profiles row
        if (newAuthId && targetAuthId && targetAuthId !== newAuthId) {
          await supabaseAdmin.from('profiles').update({ id: newAuthId }).eq('id', targetAuthId);
        }
      }
    } else {
      return NextResponse.json({ error: `Could not resolve partner email or ID "${partnerId}".` }, { status: 404 });
    }

    // 3. Safely attempt to update public.profiles password column if it exists
    try {
      await supabaseAdmin
        .from('profiles')
        .update({ password: newPassword })
        .or(`id.eq.${targetAuthId || partnerId},email.eq.${targetEmail}`);
    } catch (e) {
      // Ignore if profiles table does not have password column
    }

    return NextResponse.json({
      success: true,
      message: `Successfully reset password for partner (${targetEmail || partnerId}) in Supabase Auth.`,
    });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Server error' }, { status: 500 });
  }
}
export async function DELETE(req: Request) {
  try {
    const adminHeader = req.headers.get('x-admin-password');
    const masterPassword = process.env.ADMIN_PASSWORD || 'Primescore@Admin2026';

    if (adminHeader !== masterPassword) {
      return NextResponse.json({ error: 'Unauthorized admin request.' }, { status: 401 });
    }

    const { partnerId } = await req.json();
    if (!partnerId) {
      return NextResponse.json({ error: 'partnerId is required.' }, { status: 400 });
    }

    // Delete from Supabase Auth by user ID
    const { error } = await supabaseAdmin.auth.admin.deleteUser(partnerId);
    if (error) {
      // Don't fail hard — user may not have an auth account (e.g., legacy profiles)
      console.warn(`Auth account deletion note for ${partnerId}:`, error.message);
    }

    return NextResponse.json({ success: true, message: `Auth account deleted for ${partnerId}` });
  } catch (err: any) {
    return NextResponse.json({ error: err.message || 'Server error' }, { status: 500 });
  }
}
