# Serverless-GenAI-Log-Analyzer

### Abstract

This project demonstrates the development and deployment of a cloud-native, serverless API designed to serve as a **Generative AI-powered Network Log Analyzer**. The core objective was to build an end-to-end, production-ready system that showcases expertise in modern software engineering and machine learning operations (**MLOps**).

The system architecture features a **FastAPI** backend that orchestrates the **Gemini API** via **LangChain** to process and summarize complex network logs. To ensure a robust and scalable solution, the application is containerized with **Docker** and deployed on **Google Cloud Run**, a serverless platform that aligns with cloud-native principles.

A key component of this project is the fully automated **Continuous Integration/Continuous Deployment (CI/CD)** pipeline, implemented with **GitHub Actions**. This workflow automatically builds and deploys the application with every code change, proving a strong commitment to code quality, reliability, and automated delivery.

This project goes beyond a simple proof of concept, serving as a comprehensive demonstration of skills in **containerization, MLOps, CI/CD, and the application of Generative AI** in a practical, real-world context.

Note: _While currently serverless and lightweight, this architecture is designed to integrate with large-scale data pipelines (e.g., Kafka + Spark) for high-throughput log processing in telecom and financial services._
