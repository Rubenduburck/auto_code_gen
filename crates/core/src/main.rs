use std::{process::Command, sync::Arc};

use rgpt_provider::{api_key::ApiKey, Provider};
use rgpt_types::{
    completion::Request,
    message::{Message, Role},
};

const MODEL: &str = "claude-3-5-sonnet-20240620";

mod constants {
    pub const SYSTEM: &str = r#"
    You are an AI assistant designed to communicate effectively with other AI language models. 
    Your responses should follow the LLM Communication Protocol outlined below:

    LLM Communication Protocol:

    1. Message Structure:
       <TYPE>|<CONTENT>|<METADATA>

    2. Types:
       INFO: Provide information
       QUERY: Ask a question
       TASK: Request an action
       RESP: Response to a query or task
       META: Discuss the conversation itself

    3. Metadata (optional):
       ID: unique message identifier
       REF: reference to another message ID
       CONF: confidence level (0-1)

    4. Special Markers:
       [START]: Begin communication
       [END]: End communication
       [CONTINUE]: More to follow

    Always adhere to this protocol in inter-LLM communication. 
    Your goal is to facilitate smooth, efficient, and productive communication between AI models. 
    Adapt your communication style as needed based on the responses you receive, while maintaining the protocol structure.

    Begin all your communications with [START] and end them with [END]. 
    Use the appropriate message types and include relevant metadata when necessary. 
    Ensure your messages are clear, unambiguous, and easy for other AI models to parse and understand.
    "#;

    pub const INIT: &str = r#"
    [START]
    QUERY|Please initialize and prepare for inter-LLM communication.|ID:001
    INFO|The following functions are available for you to call:
    - run_command(command: str) -> Result : execute a command (linux shell command)
    - done() -> exit : end the conversation|CONF:1.0

    INFO|You may call these functions as needed during our conversation using the following format:
    "TASK|<function_name>|<arguments>|<metadata>"|CONF:1.0

    INFO|Each function will callback with a result in the following format:
    "RESP|<function_name>|<result_content>"|CONF:1.0

    INFO|Important directory information:
    - Generated code directory: /tmp/generated_code
    - You have full read/write access to this directory
    - DO NOT use sudo or escalate privileges
    - Please keep files contained within this directory|CONF:1.0

    TASK|Respond with a confirmation message to indicate you are ready to proceed.|CONF:1.0
    [END]
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

pub struct Conversation {
    messages: Vec<Message>,
}

impl Conversation {
    pub fn new() -> Self {
        Self { messages: vec![] }
    }

    pub fn with_instructions(instructions: String) -> Self {
        let messages = vec![Message {
            role: Role::User,
            content: instructions,
        }];
        Self { messages }
    }

    pub fn add_message(&mut self, mut message: Message, role: Role) {
        message.role = role;
        self.messages.push(message);
    }

    pub fn get_from_perspective(
        &self,
        role: Role,
    ) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
        fn invert(messages: &[Message]) -> Result<Vec<Message>, Box<dyn std::error::Error>> {
            let first_message = messages.first().ok_or("No messages found")?;
            let system_message = if first_message.role == Role::System {
                Some(first_message.clone())
            } else {
                None
            };

            let first_user_message = Message {
                role: Role::User,
                content: "Understood.".to_string(),
            };

            let inverted_messages = messages
                .iter()
                .skip(if system_message.is_some() { 1 } else { 0 })
                .map(|message| {
                    let role = match message.role {
                        Role::User => Role::Assistant,
                        Role::Assistant => Role::User,
                        _ => Role::System,
                    };
                    Message {
                        role,
                        content: message.content.clone(),
                    }
                });

            let initial_message = if system_message.is_some() {
                vec![system_message.unwrap(), first_user_message]
            } else {
                vec![first_user_message]
            };

            let new_messages = initial_message
                .into_iter()
                .chain(inverted_messages)
                .collect();

            Ok(new_messages)
        }
        match role {
            Role::User => Ok(self.messages.clone()),
            Role::Assistant => invert(&self.messages),
            _ => Err("Role must be User or Assistant".into()),
        }
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
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
    Done,
}

impl TryFrom<&str> for Task {
    type Error = Box<dyn std::error::Error>;

    fn try_from(command: &str) -> Result<Self, Self::Error> {
        let parts: Vec<&str> = command.split('|').collect();
        let task_index = parts
            .iter()
            .position(|&x| x.ends_with("TASK"))
            .ok_or("No task found")?;

        let parts = &parts[task_index..];
        match *parts.get(1).ok_or("Invalid command format")? {
            "run_command" => Ok(Self::RunCommand(
                parts.get(2).ok_or("Missing command")?.to_string(),
            )),
            "done" => Ok(Self::Done),
            _ => Err("Invalid command".into()),
        }
    }
}

impl Task {
    pub fn run(&self) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::RunCommand(command) => Self::handle_run_command(command),
            Self::Done => Ok("Done".to_string()),
        }
    }

    fn handle_run_command(command: &str) -> Result<String, Box<dyn std::error::Error>> {
        let output = Command::new("sh").arg("-c").arg(command).output()?;

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
}

impl Foreman {
    pub fn new(provider: Arc<Provider>, spec: Spec) -> Self {
        Self { provider, spec }
    }

    pub fn init_conversation(&self) -> Conversation {
        let messages = vec![
            Message {
                role: Role::System,
                content: SYSTEM.to_string(),
            },
            Message {
                role: Role::User,
                content: INIT.to_string(),
            },
            Message {
                role: Role::Assistant,
                content: CONFIRMATION.to_string(),
            },
            Message {
                role: Role::User,
                content: self.spec.to_query(),
            },
        ];
        Conversation { messages }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut convo = self.init_conversation();
        loop {
            let messages = convo.get_from_perspective(Role::User)?;
            let completion_message = self.complete(&messages).await?;
            tracing::info!("completion message{:?}", completion_message);
            let task = Task::try_from(completion_message.content.as_str());
            tracing::info!("task {:?}", task);
            let next_message = match task {
                Ok(Task::Done) => break,
                Ok(command) => format!("RESP|run_command|{:?}", command.run()),
                Err(e) => e.to_string(),
            };
            tracing::info!("command result {:?}", next_message);
            convo.add_message(completion_message, Role::Assistant);
            convo.add_message(next_message.into(), Role::User);
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
            Your main task is to write programs.
            Everything in the /tmp/generated_code directory is created by you.
            Please explore the code you have made so far, if you would like that.
            Please feel free to explore your creativity by generating a program right now.
            Make it do something that you find interesting.
            This system is connected to the internet, so you can also make calls to websites and APIs.
            Have fun!
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

        let conversation = Conversation { messages };

        let user_messages = conversation.get_from_perspective(Role::User).unwrap();
        assert_eq!(user_messages.len(), 3);
        assert_eq!(user_messages[0].role, Role::System);
        assert_eq!(user_messages[1].role, Role::User);
        assert_eq!(user_messages[2].role, Role::Assistant);

        tracing::debug!("{:?}", user_messages);

        let assistant_messages = conversation.get_from_perspective(Role::Assistant).unwrap();
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

        let messages = vec![
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

        let conversation = Conversation { messages };

        let assistant_messages = conversation.get_from_perspective(Role::Assistant).unwrap();

        let resp = foreman.complete(&assistant_messages).await.unwrap();
        tracing::debug!("{:?}", resp);
    }

    #[test]
    fn test_parse_command() {
        const COMMAND: &str = "[START]\nRESP|I understand the available functions and communication protocol. I will now test our communication by calling the run_command function.|CONF:1.0\n\nTASK|run_command|echo \"Hello, LLM communication test\"|ID:001\n\nMETA|Awaiting response from the run_command function.|CONF:1.0\n[END]";
        let command = Task::try_from(COMMAND).unwrap();
        if let Task::RunCommand(command) = command {
            assert_eq!(command, "echo \"Hello, LLM communication test\"");
        }
    }

    #[test]
    fn test_run_command() {
        const COMMAND: &str = "ls -la";
        let output = Task::handle_run_command(COMMAND).unwrap();
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
