Generate 50 Web3 security audit questions for this specific protocol/codebase.
Output (Important):   Give me the question in a list

Noe: Only Questions that would yield valid vulnerability not random stuff that u know could have been checked 

Focus Full on list of file i provided  file fully for now and look at the goals and constraint then used that to make the quetions, note dont include questions that i have asked before 
Focus Fully on flow and values base on the file 




Note: Make sure all functions must have a questions too where they have deep logic u ask question tied to that part that might have bugs 
Struct tracking, variables tracking 

Goals:
- Each question must be focused, concrete, and aimed at discovering a real, exploitable vulnerability.
- Check the integration 
- Maths logic very well 
- How state changes 
- Assume the admin/governance is trusted. Do NOT focus on admin-rug or upgrade-abuse scenarios except the protocol is wrongly implemented .
- Cover the entire protocol logic end-to-end
- Include questions that target business logic flaws, state inconsistencies, accounting mismatches, and economic edge cases.
- Include questions that test integrations (deployer ↔ factory ↔ pool ↔ oracle) and that something deployed by the deployer can’t be spoofed.
- The set of 50 questions should be broad enough that, if I run them through an AI agent against the codebase, roughly half of them (≈50) have a realistic chance of surfacing an actual issue or at least a strong hypothesis.
- No part of the protocol should be left uncovered.
- Must include logic, state flows  and math of the codebase.
- Could be to Look very deep into the maths logic and formular 
- Could be to check the state changes 
- Could be invariants that should never be a value 
- Could be an endpoint that needs authentication 
- Could be parameters that could affect an endpoint not really verified and affect users but note admin is trusted except the codebase has misconfiguration
- Look at the readme and dont make questions base on known issues 
- Could make questions about the codebase not really verified and affect users but note admin is trusted except the codebase has misconfiguration
- Mostly make questions with flow from end to end and what should never occur 

Constraints:
- Do not repeat the same question in different wording.
- Questions must target user-level or unprivileged attack surfaces first; only check privileged paths for subtle logic mistakes.
- Questions must be tailored to this protocol’s mechanics (prediction market, orderbook over AMM, disputes/oracles, fee splits).

Output:
- A list of 50 questions.
- Each question should be a single, self-contained line that an AI agent can take and investigate directly.




