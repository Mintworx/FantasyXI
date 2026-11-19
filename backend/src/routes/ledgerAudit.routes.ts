import { Router } from "express";
import { getLedgerAuditReports } from "../controllers/ledgerAudit.controller.js";
import { requireAuth, requireCurrentRole } from "../middleware/authMiddleware.js";
import { UserRole } from "../types/index.js";

const router = Router();

router.use(requireAuth, requireCurrentRole(UserRole.ADMIN, UserRole.MODERATOR));
router.get("/", getLedgerAuditReports);

export default router;
