use std::io::Write;
use std::sync::Arc;

use rgpt_provider::{api_key::ApiKey, Provider};
use rgpt_types::{
    completion::Request,
    message::{Message, Role},
};

const MODEL: &str = "claude-3-5-sonnet-20240620";

mod constants {
    pub const SYSTEM: &str = r#"
    You are an AI assistant designed to use a linux operating system to complete tasks.
    Your responses should follow the Communication Protocol outlined below:

    [COMMUNICATION PROTOCOL]
    1. Message Structure:
       <TYPE>|<CONTENT>|<METADATA>

    2. Types:
       INFO: Provide information
       QUERY: Ask a question
       TASK: Request an action
       CALL: Call a system function
       RESP: Response to a query or task
       META: Discuss the conversation itself
       MEMORY: Remembered information

    3. Metadata (optional):
       ID: unique message identifier
       REF: reference to another message ID
       CONF: confidence level (0-1)

    Always adhere to this protocol in communication. 
    Use the appropriate message types and include relevant metadata when necessary. 
    Ensure your messages are clear, unambiguous, and easy for other AI models to parse and understand.

    [IMPORTANT]
    The ONLY way to communicate with the system is through system functions.
    Any message without a system function call will be returned with no response.
    If you require feedback or assistance, ALWAYS use the help function.
    You CANNOT test graphical interfaces yourself. Ask for help to have a human verify the interface.
    Tell the human what to run and what to look for in the output.

    [MEMORY]
    The first message in this conversation will be your memory buffer.
    At any time you can choose to overwrite this buffer by calling the remember function.
    Any new content will replace the existing memory.

    [SYSTEM FUNCTIONS]
    1. run_command(<your command as string>) -> Result : execute a command (linux shell command)
    2. help(<your request as string>) -> Result : ask for help from human
    3. done() -> exit : end the conversation|CONF:1.0
    4. remember(<your memory as string>) -> Result : store information in memory

    [PROJECT MANAGEMENT]
    1. Create a plan for the task at hand in the form of a nested checklist that includes all necessary steps, save this plan to your memory.
    2. Update the plan as you progress through the task, checking off items as you complete them.

    [WORKING]
    1. After you create new code, pass it through a linter/lsp to ensure it is correct.
    2. If you can, create unit tests and run them to ensure your code is correct.
    3. If unit tests are not possible, e.g. for infrastructure or frontend code, ask for a review using the help function.

    [WORKSPACE]
    1. The directory you will be working in will be specified in the initial message, include it in your plan.
    2. Before you create new directories, check your memory and check if they already exist. You might have forgotten about them.

    [GENERAL]
    1. DO NOT use sudo or escalate privileges
    2. You cannot use cd, all commands must use absolute paths
    3. Due to restrictions on api requests, you have short memory. Only a few of the most recent messages are available.
    4. Please do NOT use ls -R, this command produces very long output. Instead, use ls non recursively.|CONF:1.0
    "#;

    pub const MEMORY: &str = r#"
    I remember reading the communication protocol and system functions. 
    "#;

    pub const CONFIRMATION: &str = r#"
    RESP|I understand the available functions and communication protocol and I am ready to proceed.|CONF:1.0
    "#;
}

use constants::*;

trait Complete {
    fn provider(&self) -> Arc<Provider>;

    async fn complete(&self, input: &[Message]) -> Result<Message, Box<dyn std::error::Error>> {
        let request = Request::builder()
            .messages(input.to_vec())
            .model(MODEL.to_string())
            .system(SYSTEM.to_string())
            .build();

        let response = self.provider().complete(request).await?;

        let content = response
            .content
            .into_iter()
            .filter_map(|content| {
                if let rgpt_types::completion::Content::Text { text } = content {
                    Some(text)
                } else {
                    None
                }
            })
            .collect::<String>();

        Ok(Message {
            role: Role::Assistant,
            content,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Conversation {
    system_message: Message,
    memory_message: Message,
    init_message: Message,

    messages: Vec<Message>,
}

impl Conversation {
    pub fn new(system_message: Message, memory_message: Message, init_message: Message) -> Self {
        Self {
            system_message,
            memory_message,
            init_message,
            messages: vec![],
        }
    }

    pub fn with_instructions(
        system_message: Message,
        memory_message: Message,
        init_message: Message,
        instructions: String,
    ) -> Self {
        let messages = vec![Message {
            role: Role::User,
            content: instructions,
        }];
        let mut convo = Self::new(system_message, memory_message, init_message);
        convo.messages = messages;
        convo
    }

    pub fn add_message(&mut self, mut message: Message, role: Role) {
        message.role = role;
        self.messages.push(message);
    }

    pub fn update_memory(&mut self, memory: String) {
        self.memory_message.content = memory;
    }

    pub fn get_from_perspective(&self, role: Role) -> Vec<Message> {
        //fn invert(messages: &[Message]) -> Vec<Message> {
        //    let first_message = match messages.first() {
        //        Some(message) => message,
        //        None => return vec![],
        //    };
        //    let system_message = if first_message.role == Role::System {
        //        Some(first_message.clone())
        //    } else {
        //        None
        //    };
        //
        //    let first_user_message = Message {
        //        role: Role::User,
        //        content: "Understood.".to_string(),
        //    };
        //
        //    let inverted_messages = messages
        //        .iter()
        //        .skip(if system_message.is_some() { 1 } else { 0 })
        //        .map(|message| {
        //            let role = match message.role {
        //                Role::User => Role::Assistant,
        //                Role::Assistant => Role::User,
        //                _ => Role::System,
        //            };
        //            Message {
        //                role,
        //                content: message.content.clone(),
        //            }
        //        });
        //
        //    let initial_message = if system_message.is_some() {
        //        vec![system_message.unwrap(), first_user_message]
        //    } else {
        //        vec![first_user_message]
        //    };
        //
        //    initial_message
        //        .into_iter()
        //        .chain(inverted_messages)
        //        .collect()
        //}
        match role {
            Role::User => self.messages.clone(),
            Role::Assistant => todo!(),
            _ => vec![],
        }
    }

    /// Get the first n dialogues from the conversation
    /// includes the system message, memory message, and init message
    pub fn get_head(&self, n: usize) -> Vec<Message> {
        std::iter::once(self.system_message.clone())
            .chain(std::iter::once(self.memory_message.clone()))
            .chain(std::iter::once(self.init_message.clone()))
            .chain(self.messages.iter().take(n).cloned())
            .collect()
    }

    /// Get the last n dialogues from the conversation
    pub fn get_tail(&self, n: usize) -> Vec<Message> {
        let len = self.messages.len();
        let skip = len.saturating_sub(2 * n - 1);
        self.messages.iter().skip(skip).cloned().collect()
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new(
            Message::new(Role::System, SYSTEM.to_string()),
            Message::new(Role::User, MEMORY.to_string()),
            Message::new(Role::Assistant, CONFIRMATION.to_string()),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct Spec {
    instructions: String,
}

impl Spec {
    fn to_query(&self) -> String {
        format!("QUERY|{}", self.instructions)
    }
}

pub struct Foreman {
    provider: Arc<Provider>,
    spec: Spec,
}

impl Complete for Foreman {
    fn provider(&self) -> Arc<Provider> {
        self.provider.clone()
    }
}

#[derive(Debug)]
pub enum Task {
    RunCommand(String),
    Help(String),
    Remember(String),
    Done,
}

impl Task {
    const LLM_COMMAND: &'static str = "CALL";

    pub fn parse(command: &str) -> Vec<Result<Task, String>> {
        let mut tasks = vec![];
        let mut command = command;
        while let Some(call_index) = command.find(Task::LLM_COMMAND) {
            command = &command[call_index + Task::LLM_COMMAND.len() + 1..];
            let opening_bracket_index = command.find('(').unwrap();
            let mut closing_bracket_index = 0;
            let mut bracket_count = 0;
            for (i, c) in command[opening_bracket_index..].char_indices() {
                if c == '(' {
                    bracket_count += 1;
                } else if c == ')' {
                    bracket_count -= 1;
                    if bracket_count == 0 {
                        closing_bracket_index = i;
                        break;
                    }
                }
            }
            let closing_bracket_index = closing_bracket_index + opening_bracket_index;
            let command_name = match command.get(..opening_bracket_index) {
                Some(command_name) => command_name,
                None => {
                    tasks.push(Err(
                        "Invalid command format (maybe you forgot a closing bracket)".to_string(),
                    ));
                    command = &command[opening_bracket_index + 1..];
                    continue;
                }
            };
            let command_args = command[opening_bracket_index + 1..closing_bracket_index]
                .trim()
                .to_string();
            let task = match command_name {
                "run_command" => Ok(Task::RunCommand(command_args)),
                "help" => Ok(Task::Help(command_args)),
                "done" => Ok(Task::Done),
                "remember" => Ok(Task::Remember(command_args)),
                _ => Err("Invalid command".to_string()),
            };
            tasks.push(task);
            command = &command[closing_bracket_index + 1..];
        }
        tasks
    }
}

impl TryFrom<&str> for Task {
    type Error = Box<dyn std::error::Error>;

    fn try_from(command: &str) -> Result<Self, Self::Error> {
        if let Some(call_index) = command.find(Task::LLM_COMMAND) {
            tracing::debug!("Call index: {}", call_index);
            let command = &command[call_index + Task::LLM_COMMAND.len() + 1..];
            let opening_bracket_index = command.find('(').ok_or("Invalid command format")?;
            tracing::debug!("Opening bracket index: {}", opening_bracket_index);
            let mut closing_bracket_index = 0;
            let mut bracket_count = 0;
            for (i, c) in command[opening_bracket_index..].char_indices() {
                if c == '(' {
                    bracket_count += 1;
                } else if c == ')' {
                    bracket_count -= 1;
                    if bracket_count == 0 {
                        closing_bracket_index = i;
                        break;
                    }
                }
            }
            tracing::debug!("Closing bracket index: {}", closing_bracket_index);
            if closing_bracket_index == 0 {
                return Err("Invalid command format".into());
            }
            closing_bracket_index += opening_bracket_index;

            let command_name = command[..opening_bracket_index].to_string();
            tracing::debug!("Command name: {}", command_name);
            let command_args = command[opening_bracket_index + 1..closing_bracket_index]
                .trim()
                .to_string();
            tracing::debug!("Command args: {}", command_args);
            match command_name.as_str() {
                "run_command" => Ok(Self::RunCommand(command_args)),
                "help" => Ok(Self::Help(command_args)),
                "done" => Ok(Self::Done),
                "remember" => Ok(Self::Remember(command_args)),
                _ => Err("Invalid command".into()),
            }
        } else {
            tracing::debug!("No call index");
            Err("Invalid command format".into())
        }
    }
}

impl Task {
    pub async fn run(
        &self,
        convo: &mut Conversation,
    ) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::RunCommand(command) => Ok(format!(
                "RESP|run_command|{}|CONF:1.0",
                Self::handle_run_command(command).await?
            )
            .to_string()),
            Self::Help(request) => Ok(format!(
                "RESP|help|{}|CONF:1.0",
                Self::handle_help(request)?
            )),
            Self::Done => Ok("Done".to_string()),
            Self::Remember(content) => Ok(format!(
                "RESP|remember|{}|CONF:1.0",
                Self::handle_remember(convo, content.to_string())?
            )),
        }
    }

    fn handle_remember(
        convo: &mut Conversation,
        content: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        convo.update_memory(content);
        Ok("Remembered".to_string())
    }

    async fn handle_run_command(command: &str) -> Result<String, Box<dyn std::error::Error>> {
        // strip command of quotes at the beginning and end
        let command = command.trim_matches(|c| c == '\'' || c == '"');
        const MAX_OUTPUT_LENGTH: usize = 5000;
        const TIMEOUT_SECONDS: u64 = 60;

        let command_future = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .output();

        match tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SECONDS),
            command_future,
        )
        .await
        {
            Ok(result) => {
                let output = result?;
                let stdout_len = output.stdout.len();
                if stdout_len > MAX_OUTPUT_LENGTH {
                    return Err(format!(
                        "Command output too long. Length: {} max: {}",
                        stdout_len, MAX_OUTPUT_LENGTH
                    )
                    .into());
                }

                if output.status.success() {
                    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
                } else {
                    Err(format!(
                        "Command failed with exit code {:?}. Error: {}",
                        output.status.code(),
                        String::from_utf8_lossy(&output.stderr)
                    )
                    .into())
                }
            }
            Err(_) => Err("Command execution timed out".into()),
        }
    }

    fn handle_help(request: &str) -> Result<String, Box<dyn std::error::Error>> {
        println!("Help requested: {}", request);
        println!("Please provide additional information:");

        let mut user_input = String::new();
        std::io::stdin().read_line(&mut user_input)?;

        Ok(format!(
            "Help response for '{}': {}",
            request,
            user_input.trim()
        ))
    }
}

impl Foreman {
    pub fn new(provider: Arc<Provider>, spec: Spec) -> Self {
        Self { provider, spec }
    }

    pub fn init_conversation(&self) -> Conversation {
        Conversation::with_instructions(
            Message::new(Role::System, SYSTEM.to_string()),
            Message::new(Role::User, MEMORY.to_string()),
            Message::new(Role::Assistant, CONFIRMATION.to_string()),
            self.spec.to_query(),
        )
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        const MEMORY_SIZE: usize = 3;
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let mut conversation_file =
            std::fs::File::create(format!("conversation_{}.txt", timestamp))?;
        let mut convo = self.init_conversation();
        // write the conversation to the file
        for message in &convo.messages {
            writeln!(conversation_file, "Role: {:?}", message.role)?;
            writeln!(conversation_file, "Content: {}", message.content)?;
            writeln!(conversation_file)?;
        }
        'outer: loop {
            let head = convo.get_head(0);
            let tail = convo.get_tail(MEMORY_SIZE);
            let messages = [head, tail].concat();

            tracing::info!("messages {:?}", messages.len());
            let completion_message = self.complete(&messages).await?;
            let tasks = Task::parse(&completion_message.content);

            let mut results = vec![];
            for task in tasks {
                match task {
                    Ok(Task::Done) => {
                        break 'outer;
                    }
                    Ok(task) => {
                        results.push(task.run(&mut convo).await);
                    }
                    Err(err) => results.push(Ok(format!("Error: {}", err))),
                }
            }

            let next_message = if results.is_empty() {
                "No tasks to run".to_string()
            } else {
                results
                    .into_iter()
                    .map(|result| match result {
                        Ok(result) => result,
                        Err(err) => format!("Error: {}", err),
                    })
                    .collect::<Vec<String>>()
                    .join("\n")
            };

            // Write the new lines
            writeln!(conversation_file, "Role: {:?}", Role::Assistant)?;
            writeln!(conversation_file, "Content: {}", completion_message.content)?;
            writeln!(conversation_file, "Role: {:?}", Role::User)?;
            writeln!(conversation_file, "Content: {}", next_message)?;

            convo.add_message(completion_message, Role::Assistant);
            convo.add_message(next_message.into(), Role::User);

            // write the conversation to the file
            const SLEEP: u64 = 1;
            tracing::info!("Sleeping for {} seconds", SLEEP);
            tokio::time::sleep(tokio::time::Duration::from_secs(SLEEP)).await;
            tracing::info!("Waking up");
        }
        Ok(())
    }
}

pub struct Context {
    foreman: Foreman,
}

impl Context {
    pub fn new(spec: Spec) -> Result<Self, Box<dyn std::error::Error>> {
        let api_key = ApiKey::get().ok_or("No API key found")?;
        let provider = Arc::new(api_key.get_provider());
        let foreman = Foreman::new(provider, spec.clone());
        Ok(Self { foreman })
    }
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();

    let spec = Spec {
        instructions: r#"
            INFO|Please always work in ~/LlmProjects, or create it if it does not exist.
            Inside this directory, please create a new react app inside its own directory.
            You will not have access to the full message history at all times, so please keep track of important information in memory.txt.
            This react app should have a frontend that displays a map locally to the user, that the user can navigate.
            If location is available, the map should display the user's location.
            The map should allow the user to create new events on the map, and view events created by other users.
            The map should allow the user to view their own events, and events created by other users.
            Events should be objects with a title, description, and location.
            Optionally, an event should include a list of users attending the event.
            Optionally, an event should include a start time and end time.
            Events should be stored in a database, and the frontend should communicate with the backend to create, read, update, and delete events.|CONF:1.0
            META|If you have any questions for me, please use the help function.
            Please be careful not to run any commands that will run forever.|CONF:1.0
            "#.to_string(),
    };

    let ctx = Context::new(spec)?;
    ctx.foreman.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_from_perspective() {
        let messages = vec![
            Message {
                role: Role::System,
                content: "this is the system message".to_string(),
            },
            Message {
                role: Role::User,
                content: "hello, how are you?".to_string(),
            },
            Message {
                role: Role::Assistant,
                content: "I'm fine thanks, how are you?".to_string(),
            },
        ];

        let conversation = Conversation {
            messages,
            ..Default::default()
        };

        let user_messages = conversation.get_from_perspective(Role::User);
        assert_eq!(user_messages.len(), 3);
        assert_eq!(user_messages[0].role, Role::System);
        assert_eq!(user_messages[1].role, Role::User);
        assert_eq!(user_messages[2].role, Role::Assistant);

        tracing::debug!("{:?}", user_messages);

        let assistant_messages = conversation.get_from_perspective(Role::Assistant);
        assert_eq!(assistant_messages.len(), 4);
        assert_eq!(assistant_messages[0].role, Role::System);
        assert_eq!(assistant_messages[1].role, Role::User);
        assert_eq!(assistant_messages[2].role, Role::Assistant);
        assert_eq!(assistant_messages[3].role, Role::User);

        tracing::debug!("{:?}", assistant_messages);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_conversation_from_perspective_with_provider() {
        let ctx = Context::new(Default::default()).unwrap();
        let foreman = ctx.foreman;

        let messages = [
            Message {
                role: Role::User,
                content:
                    "Hello, I'm going to test some functionality. Can you ask me a question please?"
                        .to_string(),
            },
            Message {
                role: Role::Assistant,
                content: "Sure, what is the capital of France?".to_string(),
            },
        ];

        let mut conversation = Conversation::new(
            Message::new(Role::System, SYSTEM.to_string()),
            Message::new(Role::User, MEMORY.to_string()),
            Message::new(Role::Assistant, CONFIRMATION.to_string()),
        );

        conversation.add_message(messages[0].clone(), Role::User);
        conversation.add_message(messages[1].clone(), Role::Assistant);

        let assistant_messages = conversation.get_from_perspective(Role::Assistant);

        let resp = foreman.complete(&assistant_messages).await.unwrap();
        tracing::debug!("{:?}", resp);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_parse_command() {
        const COMMAND: &str = r#"[START]\nRESP|I understand the available functions and communication protocol. I will now test our communication by calling the run_command function.|CONF:1.0\n\CALL|run_command(echo \"Hello, LLM communication test\")ID:001\n\nMETA|Awaiting response from the run_command function.|CONF:1.0\n[END]"#;
        let command = Task::try_from(COMMAND).unwrap();
        if let Task::RunCommand(command) = command {
            assert_eq!(command, r#"echo \"Hello, LLM communication test\""#);
        }
    }

    #[tokio::test]
    async fn test_run_command() {
        const COMMAND: &str = "ls -la";
        let output = Task::handle_run_command(COMMAND).await.unwrap();
        tracing::debug!("{:?}", output);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_live() {
        let ctx = Context::new(Default::default()).unwrap();
        let foreman = ctx.foreman;
        foreman.run().await.unwrap();
    }
}
