import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { WebhookEvent } from "@clerk/nextjs/server";
import { Webhook } from "svix";
import { api } from "./_generated/api";

const http = httpRouter();

http.route({
  path: "/clerk-webhook",
  method: "POST",
  handler: httpAction(async (ctx, request): Promise<Response> => {
    const webhookSecret = process.env.CLERK_WEBHOOK_SECRET;
    if (!webhookSecret) {
      throw new Error("Missing CLERK_WEBHOOK_SECRET environment variable");
    }

    const svix_id = request.headers.get("svix-id");
    const svix_signature = request.headers.get("svix-signature");
    const svix_timestamp = request.headers.get("svix-timestamp");

    if (!svix_id || !svix_signature || !svix_timestamp) {
      return new Response("Missing Svix headers", { status: 400 });
    }

    const payload = await request.json();
    const body = JSON.stringify(payload);

    const wh = new Webhook(webhookSecret);
    let evt: WebhookEvent;

    try {
      evt = wh.verify(body, {
        "svix-id": svix_id,
        "svix-timestamp": svix_timestamp,
        "svix-signature": svix_signature,
      }) as WebhookEvent;
    } catch (err) {
      console.error("Error verifying Clerk webhook:", err);
      return new Response("Invalid webhook signature", { status: 400 });
    }

    const eventType = evt.type;

    if (eventType === "user.created") {
      const { id, email_addresses, first_name, last_name, image_url } = evt.data;
      const email = email_addresses[0].email_address;
      const name = `${first_name || ""} ${last_name || ""}`.trim();

      try {
        const existingUser = await ctx.runQuery(api.users.getUserByClerkId, {
          clerkId: id,
        });

        if (existingUser) {
          console.log(`[INFO] Clerk ID ${id} already exists. Skipping.`);
          return new Response("User already exists", { status: 200 });
        }

        await ctx.runMutation(api.users.syncUser, {
          clerkId: id,
          email,
          name,
          image: image_url,
        });

        console.log(`[SUCCESS] Synced user ${email} (${id})`);
        return new Response("User created", { status: 200 });

      } catch (error: any) {
        console.error(`[ERROR] Failed to sync user ${email} (${id}):`, error.message || error);
        return new Response("Internal server error", { status: 500 });
      }
    }

    // ✅ Add a default return for all other event types
    return new Response("Unhandled event type", { status: 200 });
  }),
});

export default http;
