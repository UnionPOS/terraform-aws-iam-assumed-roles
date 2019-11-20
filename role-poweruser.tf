locals {
  power_user_names = length(var.power_user_names) > 0 ? true : false
  role_power_name  = join("", aws_iam_role.power.*.name)
}

module "power_label" {
  source     = "git::https://github.com/UnionPOS/terraform-null-label.git?ref=up"
  namespace  = var.namespace
  stage      = var.stage
  name       = var.power_name
  delimiter  = var.delimiter
  attributes = var.attributes
  tags       = var.tags
}

resource "aws_iam_policy" "manage_mfa_power" {
  count       = var.enabled ? 1 : 0
  name        = "${module.power_label.id}-permit-mfa"
  description = "Allow power users to manage Virtual MFA Devices"
  policy      = join("", data.aws_iam_policy_document.manage_mfa.*.json)
}

resource "aws_iam_policy" "allow_change_password_power" {
  count       = var.enabled ? 1 : 0
  name        = "${module.power_label.id}-permit-change-password"
  description = "Allow power users to change password"
  policy = join(
    "",
    data.aws_iam_policy_document.allow_change_password.*.json,
  )
}

resource "aws_iam_policy" "allow_key_management_power" {
  name        = "${module.power_label.id}-permit-manage-keys"
  description = "Allow power users to manage their own access keys"
  policy      = data.aws_iam_policy_document.allow_key_management.json
}

data "aws_iam_policy_document" "assume_role_power" {
  statement {
    actions   = ["sts:AssumeRole"]
    resources = [join("", aws_iam_role.power.*.arn)]
  }
}

resource "aws_iam_policy" "assume_role_power" {
  count       = var.enabled ? 1 : 0
  name        = "${module.power_label.id}-permit-assume-role"
  description = "Allow assuming power role"
  policy      = join("", data.aws_iam_policy_document.assume_role_power.*.json)
}

resource "aws_iam_role" "power" {
  count              = var.enabled ? 1 : 0
  name               = module.power_label.id
  assume_role_policy = join("", data.aws_iam_policy_document.role_trust.*.json)
}

resource "aws_iam_role_policy_attachment" "power" {
  count      = var.enabled ? 1 : 0
  role       = join("", aws_iam_role.power.*.name)
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_group" "power" {
  count = var.groups_enabled ? 1 : 0
  name  = module.power_label.id
}

resource "aws_iam_group_policy_attachment" "assume_role_power" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.power.*.name)
  policy_arn = join("", aws_iam_policy.assume_role_power.*.arn)
}

resource "aws_iam_group_policy_attachment" "manage_mfa_power" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.power.*.name)
  policy_arn = join("", aws_iam_policy.manage_mfa_power.*.arn)
}

resource "aws_iam_group_policy_attachment" "allow_change_password_power" {
  count      = var.groups_enabled ? 1 : 0
  group      = join("", aws_iam_group.power.*.name)
  policy_arn = join("", aws_iam_policy.allow_change_password_power.*.arn)
}

resource "aws_iam_group_policy_attachment" "key_management_power" {
  count      = var.groups_enabled ? 1 : 0
  group      = aws_iam_group.power[0].name
  policy_arn = aws_iam_policy.allow_key_management_power.arn
}

resource "aws_iam_group_membership" "power" {
  count = var.groups_enabled && local.power_user_names ? 1 : 0
  name  = module.power_label.id
  group = join("", aws_iam_group.power.*.id)
  users = var.power_user_names
}

