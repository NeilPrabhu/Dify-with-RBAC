# team_service.py

from portal.models import Team, User
from extensions.ext_database import db
import logging

logger = logging.getLogger(__name__)

class TeamService:
    @staticmethod
    def add_member_to_teams(user_id: int, team_identifiers: list[str]) -> dict:
        """
        Add a member to multiple teams.
        
        :param user_id: ID of the user to be added to the teams
        :param team_ids: List of team IDs to which the user should be added
        :return: A dictionary with the status of the operation
        """
        try:
            user = User.query.get_or_404(user_id)
            #teams = Team.query.filter(Team.id.in_(team_ids)).all()
            teams = TeamService._get_teams_by_identifiers(team_identifiers)


            if not teams:
                return {"error": "No valid teams found for the provided IDs"}

            for team in teams:
                if user not in user.teams:
                    user.teams.append(team)
                    logger.info(f"Added member {user.to_dict()} to team {team.to_dict()}")

            db.session.commit()
            return {"message": "User added to teams successfully", "user": user.to_dict(), "teams": [team.to_dict() for team in teams]}
        except Exception as e:
            logger.error(f"Error adding member to teams: {e}")
            return {"error": f"Error adding member to teams: {str(e)}"}

    @staticmethod
    def remove_member_from_teams(user_id: int, team_identifiers: list[int]) -> dict:
        """
        Remove a member from multiple teams.
        
        :param user_id: ID of the user to be removed from the teams
        :param team_ids: List of team IDs from which the user should be removed
        :return: A dictionary with the status of the operation
        """
        try:
            user = User.query.get_or_404(user_id)
            teams = TeamService._get_teams_by_identifiers(team_identifiers)

            if not teams:
                return {"error": "No valid teams found for the provided IDs"}

            for team in teams:
                if user in user.teams:
                    user.teams.remove(user)
                    logger.info(f"Removed member {user.to_dict()} from team {team.to_dict()}")

            db.session.commit()
            return {"message": "User removed from teams successfully", "user": user.to_dict(), "teams": [team.to_dict() for team in teams]}
        except Exception as e:
            logger.error(f"Error removing member from teams: {e}")
            return {"error": f"Error removing member from teams: {str(e)}"}

    @staticmethod
    def get_teams_for_user_by_username(username: str) -> dict:
        """
        Get all teams a user is part of by username.
        
        :param username: Username of the user
        :return: A dictionary with the user's teams
        """
        try:
            user = User.query.filter_by(username=username).first_or_404()
            teams = user.teams
            return {"user": user.to_dict(), "teams": [team.to_dict() for team in teams]}
        except Exception as e:
            logger.error(f"Error retrieving teams for user by username: {e}")
            return {"error": f"Error retrieving teams for user by username: {str(e)}"}
        
    @staticmethod
    def add_user_to_team_by_username_and_team_name(username: str, team_name: str) -> dict:
        """
        Add a user to a team by their username and team name.
        
        :param username: Username of the user to be added to the team
        :param team_name: Name of the team to which the user should be added
        :return: A dictionary with the status of the operation
        """
        try:
            user = User.query.filter_by(username=username).first_or_404()
            team = Team.query.filter_by(name=team_name).first_or_404()

            if user not in team.users:
                team.users.append(user)
                db.session.commit()
                logger.info(f"Added user {user.to_dict()} to team {team.to_dict()}")
                return {"message": "User added to team successfully", "user": user.to_dict(), "team": team.to_dict()}
            else:
                return {"error": "User is already a member of the team"}
        except Exception as e:
            logger.error(f"Error adding user to team: {e}")
            return {"error": f"Error adding user to team: {str(e)}"}

    @staticmethod
    def _get_teams_by_identifiers(identifiers: list) -> list:
        """
        Retrieve teams by a list of identifiers (IDs or names).
        
        :param identifiers: List of team IDs or names
        :return: List of Team objects
        """
        if not identifiers:
            return []

        if all(isinstance(identifier, int) for identifier in identifiers):
            return Team.query.filter(Team.id.in_(identifiers)).all()
        elif all(isinstance(identifier, str) for identifier in identifiers):
            return Team.query.filter(Team.name.in_(identifiers)).all()
        else:
            raise ValueError("Identifiers must be all integers (IDs) or all strings (names)")