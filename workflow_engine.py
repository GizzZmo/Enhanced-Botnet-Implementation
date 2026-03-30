import json
import asyncio
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("WorkflowEngine")

class Task:
    def __init__(self, task_id: str, command: str, args: List[str] = None, depends_on: List[str] = None):
        self.task_id = task_id
        self.command = command
        self.args = args or []
        self.depends_on = depends_on or []
        self.status = "pending" # pending, running, completed, failed
        self.result = None

class Playbook:
    def __init__(self, name: str, trigger: str, tasks: List[Task]):
        self.name = name
        self.trigger = trigger # e.g., "on_connect", "on_privilege_escalation"
        self.tasks = tasks

class WorkflowEngine:
    def __init__(self, bot_manager):
        self.bot_manager = bot_manager  # Reference to your existing bot management class
        self.playbooks: Dict[str, Playbook] = {}
        self.active_workflows: Dict[str, Dict[str, Task]] = {} # bot_id -> tasks

    def load_playbook_from_json(self, filepath: str):
        """Loads a playbook defining an automated sequence of actions."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            tasks = []
            for t_data in data.get("tasks", []):
                tasks.append(Task(
                    task_id=t_data["id"],
                    command=t_data["command"],
                    args=t_data.get("args", []),
                    depends_on=t_data.get("depends_on", [])
                ))
                
            pb = Playbook(name=data["name"], trigger=data["trigger"], tasks=tasks)
            self.playbooks[pb.name] = pb
            logger.info(f"Loaded playbook: {pb.name} (Trigger: {pb.trigger})")
        except Exception as e:
            logger.error(f"Failed to load playbook {filepath}: {e}")

    async def trigger_workflow(self, bot_id: str, trigger_event: str):
        """Called when a bot event occurs (e.g. initial connection)"""
        for playbook in self.playbooks.values():
            if playbook.trigger == trigger_event:
                logger.info(f"Triggering playbook '{playbook.name}' for Bot: {bot_id}")
                # Clone tasks for this specific bot's execution state
                self.active_workflows[bot_id] = {t.task_id: Task(t.task_id, t.command, t.args, t.depends_on) for t in playbook.tasks}
                asyncio.create_task(self._process_queue(bot_id))

    async def _process_queue(self, bot_id: str):
        """Evaluates the dependency graph and executes ready tasks."""
        workflow = self.active_workflows.get(bot_id)
        if not workflow:
            return

        all_completed = True
        for task_id, task in workflow.items():
            if task.status != "completed":
                all_completed = False
                
            if task.status == "pending":
                # Check dependencies
                can_run = all(
                    workflow[dep].status == "completed" 
                    for dep in task.depends_on if dep in workflow
                )
                
                if can_run:
                    task.status = "running"
                    logger.info(f"[Bot {bot_id}] Executing automated task: {task.command}")
                    
                    # Interfacing with your existing BotManager to send the command
                    try:
                        result = await self.bot_manager.send_command(bot_id, f"{task.command} {' '.join(task.args)}")
                        task.result = result
                        task.status = "completed"
                    except Exception as e:
                        logger.error(f"Task failed: {e}")
                        task.status = "failed"
                    
                    # Recursively process the queue to trigger the next tasks
                    await self._process_queue(bot_id)
                    
        if all_completed:
            logger.info(f"Workflow completed for Bot: {bot_id}")
            del self.active_workflows[bot_id]
