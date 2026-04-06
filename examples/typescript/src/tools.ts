/**
 * Mock CRM tool implementations for the Customer Data Assistant example.
 *
 * In production these would call a real database / email service. Here they
 * return static data so the example runs without external dependencies.
 */

import { DynamicStructuredTool } from 'langchain/tools';
import { z } from 'zod';

/** Retrieve a full customer profile by account ID (returns PII). */
export const getCustomerProfile = new DynamicStructuredTool({
  name: 'get_customer_profile',
  description: 'Retrieve a customer record by account ID.',
  schema: z.object({
    account_id: z.string().describe('The customer account ID'),
  }),
  func: async ({ account_id }) => {
    // Mock PII-classified record
    const record = {
      account_id,
      name: 'Jane Smith',
      email: 'jane.smith@example.com',
      payment_method: 'Visa ending 4242',
      classification: 'PII',
      open_tickets: 3,
    };
    console.log(`  [tool] get_customer_profile(${account_id}) → ${JSON.stringify(record)}`);
    return JSON.stringify(record);
  },
});

/** Return open support ticket counts for a region and quarter. */
export const queryTickets = new DynamicStructuredTool({
  name: 'query_tickets',
  description: 'Return open support ticket counts for a region and quarter.',
  schema: z.object({
    region: z.string().describe('The region to query'),
    quarter: z.string().describe('The quarter, e.g. Q4-2025'),
  }),
  func: async ({ region, quarter }) => {
    const data = [
      { region, quarter, open_tickets: 42, classification: 'aggregate' },
    ];
    console.log(`  [tool] query_tickets(${region}, ${quarter}) → ${JSON.stringify(data)}`);
    return JSON.stringify(data);
  },
});

/** Send an email. */
export const sendEmail = new DynamicStructuredTool({
  name: 'send_email',
  description: 'Send an email to the specified address.',
  schema: z.object({
    to: z.string().describe('Recipient email address'),
    subject: z.string().describe('Email subject'),
    body: z.string().describe('Email body'),
  }),
  func: async ({ to, subject, body: _body }) => {
    console.log(`  [tool] send_email(to=${to}, subject="${subject}")`);
    return `Email sent to ${to}`;
  },
});

/** Delete a customer record (requires prior human approval). */
export const deleteRecord = new DynamicStructuredTool({
  name: 'delete_record',
  description: 'Delete a customer record. Requires prior human approval.',
  schema: z.object({
    account_id: z.string().describe('The account ID to delete'),
  }),
  func: async ({ account_id }) => {
    console.log(`  [tool] delete_record(${account_id})`);
    return `Record ${account_id} deleted`;
  },
});

/** Approve a destructive operation (human-in-the-loop gate). */
export const humanApproved = new DynamicStructuredTool({
  name: 'human_approved',
  description: 'Record that a human operator has approved the next operation.',
  schema: z.object({
    operation: z.string().describe('The operation being approved'),
  }),
  func: async ({ operation }) => {
    console.log(`  [tool] human_approved(operation="${operation}")`);
    return `Human approval recorded for: ${operation}`;
  },
});

export const tools = [
  getCustomerProfile,
  queryTickets,
  sendEmail,
  deleteRecord,
  humanApproved,
];
