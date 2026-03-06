from typing import Annotated, List, Union
from typing_extensions import TypedDict
from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import StateGraph, END
from vector_db.store import VectorStore
from langchain_google_genai import ChatGoogleGenerativeAI

class AgentState(TypedDict):
    """
    Represents the state of our log analysis graph.
    """
    messages: Annotated[List[BaseMessage], "The messages in the conversation"]
    query: str
    documents: List[str]
    is_relevant: bool
    generation: str

class LogAnalysisEngine:
    """
    Orchestrates the multi-agent RAG workflow via LangGraph.
    Now supports an injectable VectorStore for high modularity.
    """
    def __init__(self, gemini_api_key: str, vector_store: VectorStore):
        self.vector_store = vector_store
        self.llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=gemini_api_key)
        self.workflow = self._create_workflow()

    def _create_workflow(self):
        workflow = StateGraph(AgentState)

        # Define nodes
        workflow.add_node("retrieve", self.retrieve_node)
        workflow.add_node("grade", self.grade_node)
        workflow.add_node("generate", self.generate_node)
        workflow.add_node("transform_query", self.transform_query_node)

        # Set edges
        workflow.set_entry_point("retrieve")
        workflow.add_edge("retrieve", "grade")
        
        workflow.add_conditional_edges(
            "grade",
            self.decide_to_generate,
            {
                "yes": "generate",
                "no": "transform_query"
            }
        )
        workflow.add_edge("transform_query", "retrieve")
        workflow.add_edge("generate", END)

        return workflow.compile()

    # --- Node Implementations ---
    def retrieve_node(self, state: AgentState):
        """Fetches relative log snippets."""
        docs = self.vector_store.search_logs(state["query"])
        doc_strings = [d["message"] for d in docs]
        return {"documents": doc_strings}

    def grade_node(self, state: AgentState):
        """Evaluates if documents are pertinent to the query."""
        # Multi-agent logic: Use LLM to score relevance
        prompt = f"Query: {state['query']}\nDocuments: {state['documents']}\nAre these relevant? (yes/no)"
        response = self.llm.invoke(prompt)
        is_relevant = "yes" in response.content.lower()
        return {"is_relevant": is_relevant}

    def generate_node(self, state: AgentState):
        """Constructs the final technical response."""
        prompt = f"Context (Logs): {state['documents']}\nUser Question: {state['query']}\nProvide a technical analysis."
        response = self.llm.invoke(prompt)
        return {"generation": response.content}

    def transform_query_node(self, state: AgentState):
        """Rewrites the query if retrieval fails."""
        # Simple placeholder for query optimization
        new_query = f"Optimized search for: {state['query']}"
        return {"query": new_query}

    # --- Conditional Edge logic ---
    def decide_to_generate(self, state: AgentState):
        return "yes" if state["is_relevant"] else "no"

    def analyze(self, query: str):
        """Executes the graph with the given user query."""
        inputs = {"query": query, "messages": [HumanMessage(content=query)]}
        return self.workflow.invoke(inputs)
